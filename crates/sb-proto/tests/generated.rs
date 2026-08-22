//! Checks that the generated code exists and has the expected shape.
//! If the `.proto` changes incompatibly, this breaks.

use sb_proto::{
    Capability, Check, Field, FieldType, InfoResponse, PROTOCOL_VERSION, PreflightResponse,
    Progress,
};

#[test]
fn the_generated_types_exist_and_can_be_built() {
    let info = InfoResponse {
        name: "mock".into(),
        version: "0.1.0".into(),
        protocol_version: PROTOCOL_VERSION,
        capabilities: vec![Capability::Source as i32],
    };
    assert_eq!(info.protocol_version, 1);
    assert_eq!(info.capabilities, vec![Capability::Source as i32]);
}

#[test]
fn a_plugin_can_declare_both_capabilities() {
    let info = InfoResponse {
        name: "mock".into(),
        version: "0.1.0".into(),
        protocol_version: PROTOCOL_VERSION,
        capabilities: vec![Capability::Source as i32, Capability::Storage as i32],
    };
    assert_eq!(info.capabilities.len(), 2);
}

#[test]
fn a_secret_field_is_represented_correctly() {
    let f = Field {
        name: "password".into(),
        r#type: FieldType::String as i32,
        required: true,
        secret: true,
        description: "database password".into(),
        default_value: String::new(),
    };
    assert!(f.secret);
    assert_eq!(f.r#type, FieldType::String as i32);
}

#[test]
fn the_configuration_values_cover_all_four_types() {
    use sb_proto::{StringList, Value, value::Kind};

    let text = Value {
        kind: Some(Kind::StringValue("x".into())),
    };
    let integer = Value {
        kind: Some(Kind::IntValue(5432)),
    };
    let boolean = Value {
        kind: Some(Kind::BoolValue(true)),
    };
    let list = Value {
        kind: Some(Kind::ListValue(StringList {
            values: vec!["a".into(), "b".into()],
        })),
    };

    assert!(matches!(text.kind, Some(Kind::StringValue(_))));
    assert!(matches!(integer.kind, Some(Kind::IntValue(5432))));
    assert!(matches!(boolean.kind, Some(Kind::BoolValue(true))));
    assert!(matches!(list.kind, Some(Kind::ListValue(_))));
}

#[test]
fn a_failed_check_can_carry_its_remedy() {
    // A preflight that says "it failed" without saying how to fix it is worth
    // nothing.
    let c = Check {
        name: "versions".into(),
        ok: false,
        detail: "pg_dump 14 against server 16".into(),
        remediation: "install postgresql-client-16".into(),
    };
    assert!(!c.ok);
    assert!(!c.remediation.is_empty());
}

#[test]
fn the_messages_serialize_and_deserialize() {
    use prost::Message;

    let original = Progress {
        bytes: 1_048_576,
        message: "uploading".into(),
    };
    let bytes = original.encode_to_vec();
    let round_tripped = Progress::decode(&bytes[..]).unwrap();

    assert_eq!(round_tripped.bytes, 1_048_576);
    assert_eq!(round_tripped.message, "uploading");
}

#[test]
fn a_new_field_does_not_break_an_older_reader() {
    // The property protobuf was chosen for: adding fields does not break
    // whoever was compiled without knowing about them. Simulated by decoding a
    // PreflightResponse from bytes that carry an unknown field.
    use prost::Message;

    let mut bytes = PreflightResponse {
        ok: true,
        checks: vec![],
        source_version: "16.2".into(),
    }
    .encode_to_vec();

    // Field 99, varint, value 1: something this build knows nothing about.
    bytes.extend_from_slice(&[0x98, 0x06, 0x01]);

    let round_tripped = PreflightResponse::decode(&bytes[..])
        .expect("an unknown field must be ignored, not break decoding");
    assert!(round_tripped.ok);
    assert_eq!(round_tripped.source_version, "16.2");
}

#[test]
fn the_generated_clients_and_servers_exist() {
    // Checks that build_server(true) and build_client(true) did their job. It
    // only mentions the types: if they did not exist, this would not compile.
    fn _accepts_types() {
        let _: Option<sb_proto::plugin_client::PluginClient<tonic::transport::Channel>> = None;
        let _: Option<sb_proto::source_client::SourceClient<tonic::transport::Channel>> = None;
        let _: Option<sb_proto::storage_client::StorageClient<tonic::transport::Channel>> = None;
    }
}
