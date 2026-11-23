//! Command Handlers — thin layer that parses args and dispatches to engine.
//!
//! BLOB.RDMA_HELLO: RDMA session establishment
//! BLOB.TCP_GET key
//! BLOB.RDMA_GET key rkey1 addr1 len1 [rkey2 addr2 len2 ...]
//! BLOB.TCP_SET key <data> [EX s | PX ms | EXAT unix-s | PXAT unix-ms]
//! BLOB.RDMA_SET key total_len [CRC <crc32c>] [EX s | PX ms | EXAT unix-s | PXAT unix-ms]
//!     rkey1 addr1 len1 [...]
//! BLOB.INFO key [LEN|CRC|TIER]

use std::sync::Arc;

use dma_libfabric_protocol::{decode_hex, encode_hex};
use valkey_module::{
    Context, ContextFlags, NotifyEvent, ValkeyError, ValkeyResult, ValkeyString, ValkeyValue,
    VALKEY_OK,
};

use crate::data_type::{LoValue, LO_TYPE};
use crate::engine::{self, DataSource, Expiry, Transport};
use crate::errors;
use crate::storage::ClientEFAAddress;
use crate::transport::config::FabricProvider;
use crate::transport::{self, session, Session};

/// Upper bound on client memory addresses in one EFA command.
const MAX_EFA_ADDRESSES: usize = 256;

/// Reject client commands while `largeobj.enabled` is no.
fn check_module_enabled(ctx: &Context) -> Result<(), ValkeyError> {
    if !crate::module_enabled() && !ctx.get_flags().contains(ContextFlags::REPLICATED) {
        return Err(ValkeyError::Str(errors::ERR_MODULE_DISABLED));
    }
    Ok(())
}

/// Reject GET/SET where the client cannot block: MULTI, scripts, RM_Call without
/// `K`. Uniform across modes and cache state, though some paths reply sync.
fn check_may_block(ctx: &Context) -> Result<(), ValkeyError> {
    if ctx
        .get_flags()
        .intersects(ContextFlags::DENY_BLOCKING | ContextFlags::LUA)
    {
        return Err(ValkeyError::Str(errors::ERR_DENY_BLOCKING));
    }
    Ok(())
}

/// The RDMA session the client previously established with BLOB.RDMA_HELLO.
fn efa_session(ctx: &Context) -> Result<Arc<Session>, ValkeyError> {
    session::lookup(ctx.get_client_id()).ok_or(ValkeyError::Str(errors::ERR_NO_RDMA_SESSION))
}

/// Parse the client's memory addresses from `args[start_idx..]`, which must be
/// `(rkey, addr, len)` triples. The address count is inferred from the arg count.
/// Addresses may cover more than `required_len`; only a shortfall is an error.
fn parse_efa_addresses(
    args: &[ValkeyString],
    start_idx: usize,
    required_len: u64,
) -> Result<Vec<ClientEFAAddress>, ValkeyError> {
    let tail = &args[start_idx..];
    if tail.is_empty() || !tail.len().is_multiple_of(3) {
        return Err(ValkeyError::Str(errors::ERR_MALFORMED_MEMORY_ADDR_ARGS));
    }
    let n_addrs = tail.len() / 3;
    if n_addrs > MAX_EFA_ADDRESSES {
        return Err(ValkeyError::Str(errors::ERR_TOO_MANY_MEMORY_ADDRESSES));
    }
    let mut addrs = Vec::with_capacity(n_addrs);
    let mut total_addr_len: u64 = 0;
    for i in 0..n_addrs {
        let base = i * 3;
        let rkey: u64 = tail[base]
            .to_string_lossy()
            .parse()
            .map_err(|_| ValkeyError::Str(errors::ERR_INVALID_RKEY))?;
        let addr: u64 = tail[base + 1]
            .to_string_lossy()
            .parse()
            .map_err(|_| ValkeyError::Str(errors::ERR_INVALID_MEMORY_ADDR))?;
        let len: u64 = tail[base + 2]
            .to_string_lossy()
            .parse()
            .map_err(|_| ValkeyError::Str(errors::ERR_INVALID_MEMORY_ADDR_LEN))?;
        // A zero-length address can never absorb bytes
        if 0 == len {
            return Err(ValkeyError::Str(errors::ERR_INVALID_MEMORY_ADDR_LEN));
        }
        addrs.push((addr, len as usize, rkey));
        total_addr_len = total_addr_len.saturating_add(len);
    }
    if total_addr_len < required_len {
        return Err(ValkeyError::String(format!(
            "ERR client memory address length {} smaller than object length {}",
            total_addr_len, required_len
        )));
    }
    Ok(addrs)
}

/// Parse the optional `CRC <crc32c>` token from `args[start_idx]`. Returns the
/// client-supplied CRC and the index where address triples begin. When the token
/// is absent, addresses start at `start_idx` and the CRC is None.
fn parse_optional_crc(
    args: &[ValkeyString],
    start_idx: usize,
) -> Result<(Option<u32>, usize), ValkeyError> {
    if args.len() > start_idx
        && args[start_idx]
            .to_string_lossy()
            .eq_ignore_ascii_case("CRC")
    {
        let crc: u32 = args
            .get(start_idx + 1)
            .ok_or(ValkeyError::WrongArity)?
            .to_string_lossy()
            .parse()
            .map_err(|_| ValkeyError::Str(errors::ERR_INVALID_CRC))?;
        Ok((Some(crc), start_idx + 2))
    } else {
        Ok((None, start_idx))
    }
}

/// The expire option a token names, as (milliseconds per unit, absolute), or None.
fn expiry_option(token: &ValkeyString) -> Option<(i64, bool)> {
    match token.to_string_lossy().to_ascii_uppercase().as_str() {
        "EX" => Some((1000, false)),
        "PX" => Some((1, false)),
        "EXAT" => Some((1000, true)),
        "PXAT" => Some((1, true)),
        _ => None,
    }
}

/// Parse an optional `EX seconds | PX milliseconds | EXAT unix-time-seconds |
/// PXAT unix-time-milliseconds` at `args[start_idx]`, like SET. Returns the expiry and
/// the index after it. The value must be a positive integer, and with the current time
/// added it must fit in an i64 of milliseconds, as in SET. A second expire option is an
/// error. `now_ms` is the current unix time in milliseconds.
fn parse_optional_expiry(
    args: &[ValkeyString],
    start_idx: usize,
    now_ms: i64,
) -> Result<(Option<Expiry>, usize), ValkeyError> {
    let Some((unit_ms, absolute)) = args.get(start_idx).and_then(expiry_option) else {
        return Ok((None, start_idx));
    };
    let value: i64 = args
        .get(start_idx + 1)
        .ok_or(ValkeyError::WrongArity)?
        .to_string_lossy()
        .parse()
        .map_err(|_| ValkeyError::Str(errors::ERR_INVALID_EXPIRE))?;
    let ms = match value.checked_mul(unit_ms) {
        Some(ms) if value > 0 && (absolute || ms.checked_add(now_ms).is_some()) => ms,
        _ => return Err(ValkeyError::Str(errors::ERR_INVALID_EXPIRE)),
    };
    if args.get(start_idx + 2).and_then(expiry_option).is_some() {
        return Err(ValkeyError::Str(errors::ERR_EXPIRE_CONFLICT));
    }
    let expiry = if absolute {
        Expiry::At(ms)
    } else {
        Expiry::In(ms)
    };
    Ok((Some(expiry), start_idx + 2))
}

/// As SET does with an EXAT / PXAT time that has passed: store nothing and delete the key,
/// which `exists`. Returns whether the time has passed; the command then replies OK
/// without a transfer.
fn delete_if_already_expired(
    ctx: &Context,
    key: &ValkeyString,
    exists: bool,
    expiry: Option<Expiry>,
    now_ms: i64,
) -> Result<bool, ValkeyError> {
    if !matches!(expiry, Some(Expiry::At(unix_ms)) if unix_ms <= now_ms) {
        return Ok(false);
    }
    if exists {
        ctx.open_key_writable(key).delete()?;
        ctx.notify_keyspace_event(NotifyEvent::EXPIRED, "expired", key);
    }
    Ok(true)
}

/// Whether `addr` is a well-formed sockaddr for the tcp provider: a sockaddr_in
/// (16 bytes, AF_INET) or sockaddr_in6 (28 bytes, AF_INET6). fi_av_insert reads the
/// family to pick the address length, so anything else is an over-read.
fn is_valid_sockaddr(addr: &[u8]) -> bool {
    let Some(family) = addr.get(..2).map(|b| u16::from_ne_bytes([b[0], b[1]])) else {
        return false;
    };
    let family = libc::c_int::from(family);
    matches!(
        (addr.len(), family),
        (16, libc::AF_INET) | (28, libc::AF_INET6)
    )
}

// ─── BLOB.RDMA_HELLO ───────────────────────────────────────────────────────────
//
// Establishes a fabric session with the client.
// Client sends its fabric address as hex, opaque to us and in the provider's own format. The
// server inserts it into each domain's address vector and returns an address per server,
// so both sides hold each other before the first transfer.

pub fn lo_rdma_hello(ctx: &Context, args: Vec<ValkeyString>) -> ValkeyResult {
    check_module_enabled(ctx)?;
    if args.len() != 2 {
        return Err(ValkeyError::WrongArity);
    }

    let Some(fabric) = transport::fabric() else {
        return Err(ValkeyError::Str(errors::ERR_RDMA_UNAVAILABLE));
    };

    let rdma_address = decode_hex(args[1].as_slice())
        .map_err(|_| ValkeyError::Str(errors::ERR_INVALID_RDMA_ADDR_HEX))?;
    // An EFA address is exactly 32 bytes; a tcp one must be a well-formed sockaddr, so
    // fi_av_insert never reads past the bytes the client sent.
    match crate::fabric_provider() {
        FabricProvider::EfaDirect if rdma_address.len() != 32 => {
            return Err(ValkeyError::Str(errors::ERR_RDMA_ADDR_LEN));
        }
        FabricProvider::Emulated if rdma_address.is_empty() => {
            return Err(ValkeyError::Str(errors::ERR_RDMA_ADDR_EMPTY));
        }
        FabricProvider::Emulated if !is_valid_sockaddr(&rdma_address) => {
            return Err(ValkeyError::Str(errors::ERR_RDMA_ADDR_FORMAT));
        }
        FabricProvider::EfaDirect | FabricProvider::Emulated => {}
    }

    let client_id = ctx.get_client_id();
    // One endpoint per connection. A second HELLO would hold the old address-vector entry while
    // inserting the new one; when the client's old endpoint has died and the new one reuses its
    // QPN, efa-direct cannot represent both (vdma/.claude/open_issue.md). Reconnect instead.
    if session::lookup(client_id).is_some() {
        return Err(ValkeyError::Str(errors::ERR_RDMA_SESSION_EXISTS));
    }
    fabric
        .add_peer(client_id, &rdma_address)
        .map_err(|_| ValkeyError::Str(errors::ERR_SESSION_CREATE))?;
    session::insert(client_id, Session::new(client_id, rdma_address));

    let reply: Vec<ValkeyValue> = fabric
        .local_addresses()
        .map(|address| ValkeyValue::BulkString(encode_hex(address)))
        .collect();
    Ok(ValkeyValue::Array(reply))
}

// ─── BLOB.TCP_GET ──────────────────────────────────────────────────────────────
//
// BLOB.TCP_GET key — returns object bytes inline via RESP.

pub fn lo_tcp_get(ctx: &Context, args: Vec<ValkeyString>) -> ValkeyResult {
    check_module_enabled(ctx)?;
    check_may_block(ctx)?;
    if args.len() != 2 {
        return Err(ValkeyError::WrongArity);
    }
    // Lookup LoValue in keyspace.
    let key = ctx.open_key(&args[1]);
    let lo_value: &LoValue = match key
        .get_value::<LoValue>(&LO_TYPE)
        .map_err(|_| ValkeyError::WrongType)?
    {
        Some(v) if !v.reclaim_in_progress() => v,
        _ => return Ok(ValkeyValue::Null),
    };
    let object_id = lo_value.object_id;
    let obj_len = lo_value.len;
    let crc32c = lo_value.crc32c;
    // Pin the file to protect it from asynchronous deletion in tiered mode.
    let file = lo_value.file.clone();
    // Always async: the engine blocks the client and replies from a task.
    engine::execute_get(ctx, object_id, obj_len, crc32c, file, Transport::Tcp);
    Ok(ValkeyValue::NoReply)
}

// ─── BLOB.RDMA_GET ─────────────────────────────────────────────────────────────
//
// BLOB.RDMA_GET key rkey1 addr1 len1 [rkey2 addr2 len2 ...]
// Writes object data directly to client-registered memory via RDMA.

pub fn lo_rdma_get(ctx: &Context, args: Vec<ValkeyString>) -> ValkeyResult {
    check_module_enabled(ctx)?;
    check_may_block(ctx)?;
    // At least: cmd + key + one (rkey, addr, len) triple = 5 args.
    // Incomplete triples are caught by parse_efa_addresses with a clearer error.
    if args.len() < 5 {
        return Err(ValkeyError::WrongArity);
    }
    // Lookup LoValue in keyspace.
    let key = ctx.open_key(&args[1]);
    let lo_value: &LoValue = match key
        .get_value::<LoValue>(&LO_TYPE)
        .map_err(|_| ValkeyError::WrongType)?
    {
        Some(v) if !v.reclaim_in_progress() => v,
        _ => return Ok(ValkeyValue::Null),
    };
    let object_id = lo_value.object_id;
    let obj_len = lo_value.len;
    let crc32c = lo_value.crc32c;
    // Pin the file to protect it from asynchronous deletion in tiered mode.
    let file = lo_value.file.clone();
    // BLOB.RDMA_GET key rkey1 addr1 len1 [rkey2 addr2 len2 ...]
    // Address count is inferred from the triplet args.
    let addrs = parse_efa_addresses(&args, 2, obj_len)?;
    let session = efa_session(ctx)?;
    let transport = Transport::Efa { session, addrs };
    // Always async: the engine blocks the client and replies from a task.
    engine::execute_get(ctx, object_id, obj_len, crc32c, file, transport);
    Ok(ValkeyValue::NoReply)
}

// ─── BLOB.TCP_SET ──────────────────────────────────────────────────────────────
//
// BLOB.TCP_SET key <data> [EX s | PX ms | EXAT unix-s | PXAT unix-ms] — stores inline
// bytes from the RESP payload.

pub fn lo_tcp_set(ctx: &Context, args: Vec<ValkeyString>) -> ValkeyResult {
    check_module_enabled(ctx)?;
    check_may_block(ctx)?;
    if args.len() < 3 {
        return Err(ValkeyError::WrongArity);
    }
    let now_ms = engine::now_unix_ms();
    let (expiry, end) = parse_optional_expiry(&args, 3, now_ms)?;
    if end != args.len() {
        return Err(ValkeyError::Str(errors::ERR_SYNTAX));
    }
    // Reject a key of another type before any transfer, matching valkey-bloom.
    let old_oid = ctx
        .open_key(&args[1])
        .get_value::<LoValue>(&LO_TYPE)
        .map_err(|_| ValkeyError::WrongType)?
        .map(|v| v.object_id);
    // TCP path: data.len() IS the authoritative length. No user-provided len needed.
    let obj_len = args[2].as_slice().len() as u64;
    // Reject zero-length values.
    if obj_len == 0 {
        return Err(ValkeyError::Str(errors::ERR_ZERO_LENGTH_OBJECT));
    }
    // Reject objects exceeding the configured max object size. The config
    // constraint enforces max-object-size <= segment-size, so this also
    // covers objects that would not fit in a single segment.
    let max_obj_size = crate::max_object_size();
    if obj_len > max_obj_size {
        return Err(ValkeyError::Str(errors::ERR_MAX_OBJECT_SIZE_EXCEEDED));
    }
    if delete_if_already_expired(ctx, &args[1], old_oid.is_some(), expiry, now_ms)? {
        return VALKEY_OK;
    }
    let data = args[2].as_slice();
    // Always async: the engine blocks the client and replies from a task.
    engine::execute_set_tcp(ctx, &args[1], obj_len, data, old_oid, expiry);
    Ok(ValkeyValue::NoReply)
}

// ─── BLOB.RDMA_SET ─────────────────────────────────────────────────────────────
//
// BLOB.RDMA_SET key total_len [CRC <crc32c>] [EX s | PX ms | EXAT unix-s | PXAT unix-ms]
//     rkey1 addr1 len1 [rkey2 addr2 len2 ...]
// Reads object data from client-registered memory via RDMA. When the optional
// CRC token is present, the server verifies the post-transfer CRC32C against the
// client-supplied value and rejects the SET on mismatch. The expire option sits before
// the triples: an rkey is a number, so it never reads as one.

pub fn lo_rdma_set(ctx: &Context, args: Vec<ValkeyString>) -> ValkeyResult {
    check_module_enabled(ctx)?;
    check_may_block(ctx)?;
    // At least: cmd + key + total_len + one (rkey, addr, len) triple = 6 args.
    // Incomplete triples are caught by parse_efa_addresses with a clearer error.
    if args.len() < 6 {
        return Err(ValkeyError::WrongArity);
    }
    // Reject a key of another type before any transfer, matching valkey-bloom.
    let old_oid = ctx
        .open_key(&args[1])
        .get_value::<LoValue>(&LO_TYPE)
        .map_err(|_| ValkeyError::WrongType)?
        .map(|v| v.object_id);
    // total_len is required — server needs to know how many bytes to fi_read
    // from the client.
    let obj_len: u64 = args[2]
        .to_string_lossy()
        .parse()
        .map_err(|_| ValkeyError::Str(errors::ERR_INVALID_LEN))?;
    // Reject zero-length values.
    if obj_len == 0 {
        return Err(ValkeyError::Str(errors::ERR_ZERO_LENGTH_OBJECT));
    }
    // Reject objects exceeding the configured max object size. The config
    // constraint enforces max-object-size <= segment-size, so this also
    // covers objects that would not fit in a single segment.
    let max_obj_size = crate::max_object_size();
    if obj_len > max_obj_size {
        return Err(ValkeyError::Str(errors::ERR_MAX_OBJECT_SIZE_EXCEEDED));
    }
    // Optional CRC token: "CRC <u32>" between total_len and the first address triple.
    let (client_crc, expiry_start) = parse_optional_crc(&args, 3)?;
    let now_ms = engine::now_unix_ms();
    let (expiry, addr_start) = parse_optional_expiry(&args, expiry_start, now_ms)?;
    let addrs = parse_efa_addresses(&args, addr_start, obj_len)?;
    let session = efa_session(ctx)?;
    if delete_if_already_expired(ctx, &args[1], old_oid.is_some(), expiry, now_ms)? {
        return VALKEY_OK;
    }
    let data_source = DataSource::Efa {
        session,
        addrs,
        client_crc,
    };
    // Always async: the engine blocks the client and replies from a task.
    engine::execute_set(ctx, &args[1], obj_len, data_source, old_oid, expiry);
    Ok(ValkeyValue::NoReply)
}

// ─── BLOB.INFO ─────────────────────────────────────────────────────────────────
//
// BLOB.INFO key [LEN | CRC | TIER]
//
// Parse args → resolve key → return metadata field or all fields as array.

pub fn lo_info(ctx: &Context, args: Vec<ValkeyString>) -> ValkeyResult {
    check_module_enabled(ctx)?;
    if !(2..=3).contains(&args.len()) {
        return Err(ValkeyError::WrongArity);
    }

    let key = ctx.open_key(&args[1]);
    let value = match key
        .get_value::<LoValue>(&LO_TYPE)
        .map_err(|_| ValkeyError::WrongType)?
    {
        Some(v) if !v.reclaim_in_progress() => v,
        _ => return Ok(ValkeyValue::Null),
    };

    let len = ValkeyValue::Integer(value.len as i64);
    let crc = ValkeyValue::Integer(i64::from(value.crc32c));
    let tier = ValkeyValue::SimpleStringStatic(value.tier().as_str());

    if args.len() == 2 {
        return Ok(ValkeyValue::Array(vec![
            ValkeyValue::SimpleStringStatic("len"),
            len,
            ValkeyValue::SimpleStringStatic("crc"),
            crc,
            ValkeyValue::SimpleStringStatic("tier"),
            tier,
        ]));
    }

    match args[2].to_string_lossy().to_uppercase().as_str() {
        "LEN" => Ok(len),
        "CRC" => Ok(crc),
        "TIER" => Ok(tier),
        _ => Err(ValkeyError::Str(errors::ERR_INVALID_INFO_FIELD)),
    }
}

// ─── Unit Tests ──────────────────────────────────────────────────────────────

#[cfg(all(test, feature = "enable-system-alloc"))]
mod tests {
    use super::*;

    /// Build a `Vec<ValkeyString>` from string slices using test shims.
    fn vs(args: &[&str]) -> Vec<ValkeyString> {
        args.iter().map(|s| ValkeyString::test(*s)).collect()
    }

    /// Call `parse_efa_addresses` starting at index 0 and return the error string on failure.
    fn reject(args: &[&str], required_len: u64) -> String {
        let vs = vs(args);
        match parse_efa_addresses(&vs, 0, required_len) {
            Ok(addrs) => panic!("expected rejection, parsed {addrs:?}"),
            Err(ValkeyError::Str(message)) => message.to_string(),
            Err(ValkeyError::String(message)) => message,
            Err(ValkeyError::WrongArity) => "WrongArity".to_string(),
            Err(other) => panic!("unexpected error variant: {other:?}"),
        }
    }

    #[test]
    fn addresses_parse_in_client_order() {
        // ClientEFAAddress is (addr, len, rkey) — not the arg order, which is rkey first.
        let args = vs(&["999", "4096", "8192"]);
        assert_eq!(
            parse_efa_addresses(&args, 0, 8192).unwrap(),
            vec![(4096, 8192, 999)]
        );
        // Order is load-bearing: ChunkIterator consumes addresses front to back, so the
        // object's first bytes land in the first address.
        let args = vs(&["11", "1000", "1024", "22", "9000", "3072"]);
        assert_eq!(
            parse_efa_addresses(&args, 0, 4096).unwrap(),
            vec![(1000, 1024, 11), (9000, 3072, 22)]
        );
        // A zero addr is a valid base: without FI_MR_VIRT_ADDR it is an offset into the
        // registered memory, so it must not be read as unset.
        let args = vs(&["7", "0", "4096"]);
        assert_eq!(
            parse_efa_addresses(&args, 0, 4096).unwrap(),
            vec![(0, 4096, 7)]
        );
    }

    #[test]
    fn start_idx_skips_leading_args() {
        // Simulates BLOB.RDMA_GET key rkey addr len — start_idx=2 skips "BLOB.RDMA_GET" and "key".
        let args = vs(&["BLOB.RDMA_GET", "key", "7", "64", "4096"]);
        assert_eq!(
            parse_efa_addresses(&args, 2, 4096).unwrap(),
            vec![(64, 4096, 7)]
        );
    }

    #[test]
    fn address_space_is_validated_against_the_object() {
        // Exact fit and surplus both pass.
        let args = vs(&["7", "64", "4096"]);
        assert!(parse_efa_addresses(&args, 0, 4096).is_ok());
        let args = vs(&["7", "64", "1048576"]);
        assert_eq!(
            parse_efa_addresses(&args, 0, 4096).unwrap(),
            vec![(64, 1048576, 7)]
        );
        // Shortfall is rejected.
        assert_eq!(
            reject(&["7", "64", "4095"], 4096),
            "ERR client memory address length 4095 smaller than object length 4096"
        );
        // Summed across addresses, still one byte short.
        assert_eq!(
            reject(&["7", "64", "2048", "8", "9000", "2047"], 4096),
            "ERR client memory address length 4095 smaller than object length 4096"
        );
    }

    #[test]
    fn incomplete_triples_are_rejected() {
        assert_eq!(
            reject(&[] as &[&str], 4096),
            errors::ERR_MALFORMED_MEMORY_ADDR_ARGS
        );
        assert_eq!(reject(&["7"], 4096), errors::ERR_MALFORMED_MEMORY_ADDR_ARGS);
        assert_eq!(
            reject(&["7", "64"], 4096),
            errors::ERR_MALFORMED_MEMORY_ADDR_ARGS
        );
        // One complete triple + one leftover.
        assert_eq!(
            reject(&["7", "64", "4096", "extra"], 4096),
            errors::ERR_MALFORMED_MEMORY_ADDR_ARGS
        );
    }

    #[test]
    fn too_many_addresses_are_rejected() {
        let strs: Vec<String> = (0..=MAX_EFA_ADDRESSES)
            .flat_map(|i| ["7".to_string(), (i * 4096).to_string(), "4096".to_string()])
            .collect();
        let refs: Vec<&str> = strs.iter().map(|s| s.as_str()).collect();
        assert_eq!(reject(&refs, 4096), errors::ERR_TOO_MANY_MEMORY_ADDRESSES);
    }

    #[test]
    fn malformed_triple_fields_are_rejected_by_field() {
        assert_eq!(
            reject(&["notakey", "64", "4096"], 4096),
            errors::ERR_INVALID_RKEY
        );
        assert_eq!(
            reject(&["7", "notanaddr", "4096"], 4096),
            errors::ERR_INVALID_MEMORY_ADDR
        );
        assert_eq!(
            reject(&["7", "64", "notalen"], 4096),
            errors::ERR_INVALID_MEMORY_ADDR_LEN
        );
        assert_eq!(
            reject(&["7", "64", "0"], 4096),
            errors::ERR_INVALID_MEMORY_ADDR_LEN
        );
    }

    // ─── CRC parsing tests ──────────────────────────────────────────────────

    /// Call `parse_optional_crc` starting at index 0 and return the result or error string.
    fn parse_crc(args: &[&str]) -> Result<(Option<u32>, usize), String> {
        let vs = vs(args);
        parse_optional_crc(&vs, 0).map_err(|e| match e {
            ValkeyError::Str(message) => message.to_string(),
            ValkeyError::WrongArity => "WrongArity".to_string(),
            other => panic!("unexpected error variant: {other:?}"),
        })
    }

    #[test]
    fn crc_keyword_with_no_value_eats_rkey() {
        // "CRC 999 4096 8192" — CRC consumes "999" as the CRC value, leaving
        // "4096 8192" which is not a multiple of 3 → malformed triples.
        let args = vs(&["CMD", "key", "4096", "CRC", "999", "4096", "8192"]);
        let (client_crc, addr_start) = parse_optional_crc(&args, 3).unwrap();
        assert_eq!(client_crc, Some(999));
        assert_eq!(addr_start, 5);
        // The leftover ["4096", "8192"] fails the triplet parser.
        let err = match parse_efa_addresses(&args, addr_start, 4096) {
            Err(ValkeyError::Str(msg)) => msg.to_string(),
            other => panic!("expected Str error, got {other:?}"),
        };
        assert_eq!(err, errors::ERR_MALFORMED_MEMORY_ADDR_ARGS);
    }

    #[test]
    fn crc_keyword_with_garbage_value_is_rejected() {
        assert_eq!(
            parse_crc(&["CRC", "notanumber"]),
            Err(errors::ERR_INVALID_CRC.to_string())
        );
        assert_eq!(
            parse_crc(&["CRC", "-1"]),
            Err(errors::ERR_INVALID_CRC.to_string())
        );
        assert_eq!(
            parse_crc(&["CRC", "4294967296"]),
            Err(errors::ERR_INVALID_CRC.to_string())
        ); // u32::MAX + 1
    }

    #[test]
    fn numeric_rkey_at_crc_position_falls_through() {
        // A numeric rkey like "999" at position 0 does not match the "CRC" keyword,
        // so the parser falls through to (None, 0) and the triplet parses normally.
        let (client_crc, addr_start) = parse_crc(&["999", "4096", "8192"]).unwrap();
        assert_eq!(client_crc, None);
        assert_eq!(addr_start, 0);
        let args = vs(&["999", "4096", "8192"]);
        assert_eq!(
            parse_efa_addresses(&args, addr_start, 8192).unwrap(),
            vec![(4096, 8192, 999)]
        );
    }

    // ─── Expire parsing tests ───────────────────────────────────────────────

    const NOW_MS: i64 = 1_700_000_000_000;

    /// Call `parse_optional_expiry` starting at index 0 and return the result or error string.
    fn parse_expiry(args: &[&str]) -> Result<(Option<Expiry>, usize), String> {
        let vs = vs(args);
        parse_optional_expiry(&vs, 0, NOW_MS).map_err(|e| match e {
            ValkeyError::Str(message) => message.to_string(),
            ValkeyError::WrongArity => "WrongArity".to_string(),
            other => panic!("unexpected error variant: {other:?}"),
        })
    }

    #[test]
    fn each_expire_option_parses_to_milliseconds() {
        assert_eq!(
            parse_expiry(&["EX", "10"]),
            Ok((Some(Expiry::In(10_000)), 2))
        );
        assert_eq!(parse_expiry(&["PX", "10"]), Ok((Some(Expiry::In(10)), 2)));
        assert_eq!(
            parse_expiry(&["EXAT", "1700000000"]),
            Ok((Some(Expiry::At(NOW_MS)), 2))
        );
        assert_eq!(
            parse_expiry(&["PXAT", "1700000000123"]),
            Ok((Some(Expiry::At(NOW_MS + 123)), 2))
        );
        // Not case-sensitive, like SET.
        assert_eq!(parse_expiry(&["ex", "1"]), Ok((Some(Expiry::In(1000)), 2)));
        assert_eq!(parse_expiry(&["pXaT", "1"]), Ok((Some(Expiry::At(1)), 2)));
        // A time in the past is valid, as in SET; the handler then deletes the key.
        assert_eq!(
            parse_expiry(&["EXAT", "1"]),
            Ok((Some(Expiry::At(1000)), 2))
        );
    }

    #[test]
    fn no_expire_option_parses_to_none() {
        assert_eq!(parse_expiry(&[]), Ok((None, 0)));
        // A numeric rkey is not an option, so RDMA_SET's triples start here.
        assert_eq!(parse_expiry(&["999", "4096", "8192"]), Ok((None, 0)));
        assert_eq!(parse_expiry(&["KEEPTTL"]), Ok((None, 0)));
    }

    #[test]
    fn bad_expire_values_are_rejected() {
        let invalid = Err(errors::ERR_INVALID_EXPIRE.to_string());
        for option in ["EX", "PX", "EXAT", "PXAT"] {
            assert_eq!(parse_expiry(&[option, "0"]), invalid, "{option} 0");
            assert_eq!(parse_expiry(&[option, "-1"]), invalid, "{option} -1");
            assert_eq!(parse_expiry(&[option, "1.5"]), invalid, "{option} 1.5");
            assert_eq!(parse_expiry(&[option, "ten"]), invalid, "{option} ten");
            assert_eq!(parse_expiry(&[option, ""]), invalid, "{option} empty");
            assert_eq!(
                parse_expiry(&[option, "9223372036854775808"]),
                invalid,
                "{option} i64::MAX + 1"
            );
            assert_eq!(parse_expiry(&[option]), Err("WrongArity".to_string()));
        }
        // Seconds that overflow an i64 of milliseconds.
        let max_secs = (i64::MAX / 1000).to_string();
        let over_secs = (i64::MAX / 1000 + 1).to_string();
        assert_eq!(
            parse_expiry(&["EXAT", &max_secs]).unwrap().0,
            Some(Expiry::At(i64::MAX / 1000 * 1000))
        );
        assert_eq!(parse_expiry(&["EXAT", &over_secs]), invalid);
        assert_eq!(parse_expiry(&["EX", &over_secs]), invalid);
        // A relative TTL that overflows once the current time is added.
        let max_rel = (i64::MAX - NOW_MS).to_string();
        let over_rel = (i64::MAX - NOW_MS + 1).to_string();
        assert_eq!(
            parse_expiry(&["PX", &max_rel]).unwrap().0,
            Some(Expiry::In(i64::MAX - NOW_MS))
        );
        assert_eq!(parse_expiry(&["PX", &over_rel]), invalid);
        assert_eq!(parse_expiry(&["EX", &max_secs]), invalid);
        // An absolute time has nothing added, so all of i64 fits.
        assert_eq!(
            parse_expiry(&["PXAT", &i64::MAX.to_string()]).unwrap().0,
            Some(Expiry::At(i64::MAX))
        );
    }

    #[test]
    fn a_second_expire_option_is_rejected() {
        let conflict = Err(errors::ERR_EXPIRE_CONFLICT.to_string());
        assert_eq!(parse_expiry(&["EX", "10", "PX", "10"]), conflict);
        assert_eq!(parse_expiry(&["EX", "10", "EX", "20"]), conflict);
        assert_eq!(parse_expiry(&["PXAT", "1", "exat", "1"]), conflict);
        // Anything else after the option is left for the caller.
        assert_eq!(
            parse_expiry(&["EX", "10", "7", "64", "4096"]),
            Ok((Some(Expiry::In(10_000)), 2))
        );
    }

    #[test]
    fn expire_option_follows_crc_before_the_triples() {
        // Full RDMA_SET arg shape: CMD key total_len CRC <value> EX <seconds> rkey addr len
        let args = vs(&[
            "CMD", "key", "4096", "CRC", "12345", "EX", "60", "7", "64", "4096",
        ]);
        let (client_crc, expiry_start) = parse_optional_crc(&args, 3).unwrap();
        assert_eq!(client_crc, Some(12345));
        let (expiry, addr_start) = parse_optional_expiry(&args, expiry_start, NOW_MS).unwrap();
        assert_eq!(expiry, Some(Expiry::In(60_000)));
        assert_eq!(addr_start, 7);
        assert_eq!(
            parse_efa_addresses(&args, addr_start, 4096).unwrap(),
            vec![(64, 4096, 7)]
        );
        // Without CRC, the option comes right after total_len.
        let args = vs(&["CMD", "key", "4096", "PX", "500", "7", "64", "4096"]);
        let (client_crc, expiry_start) = parse_optional_crc(&args, 3).unwrap();
        assert_eq!(client_crc, None);
        let (expiry, addr_start) = parse_optional_expiry(&args, expiry_start, NOW_MS).unwrap();
        assert_eq!(expiry, Some(Expiry::In(500)));
        assert_eq!(addr_start, 5);
    }

    #[test]
    fn crc_token_shifts_address_start() {
        // Full RDMA_SET arg shape: CMD key total_len CRC <value> rkey addr len
        // parse_optional_crc at index 3 consumes "CRC 12345" and returns addr_start=5.
        // parse_efa_addresses at index 5 picks up the valid triple.
        let args = vs(&["CMD", "key", "4096", "CRC", "12345", "7", "64", "4096"]);
        let (client_crc, addr_start) = parse_optional_crc(&args, 3).unwrap();
        assert_eq!(client_crc, Some(12345));
        assert_eq!(addr_start, 5);
        assert_eq!(
            parse_efa_addresses(&args, addr_start, 4096).unwrap(),
            vec![(64, 4096, 7)]
        );
    }
}
