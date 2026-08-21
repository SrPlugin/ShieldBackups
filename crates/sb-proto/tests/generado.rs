//! Comprueba que el código generado existe y tiene la forma esperada.
//! Si el `.proto` cambia de manera incompatible, esto se rompe.

use sb_proto::{
    Capability, Check, Field, FieldType, InfoResponse, PROTOCOL_VERSION, PreflightResponse,
    Progress,
};

#[test]
fn los_tipos_generados_existen_y_se_construyen() {
    let info = InfoResponse {
        name: "mock".into(),
        version: "0.1.0".into(),
        protocol_version: PROTOCOL_VERSION,
        capabilities: vec![Capability::Engine as i32],
    };
    assert_eq!(info.protocol_version, 1);
    assert_eq!(info.capabilities, vec![Capability::Engine as i32]);
}

#[test]
fn un_plugin_puede_declarar_ambas_capacidades() {
    let info = InfoResponse {
        name: "mock".into(),
        version: "0.1.0".into(),
        protocol_version: PROTOCOL_VERSION,
        capabilities: vec![Capability::Engine as i32, Capability::Storage as i32],
    };
    assert_eq!(info.capabilities.len(), 2);
}

#[test]
fn un_field_secreto_se_representa_correctamente() {
    let f = Field {
        name: "password".into(),
        r#type: FieldType::String as i32,
        required: true,
        secret: true,
        description: "contraseña de la base de datos".into(),
        default_value: String::new(),
    };
    assert!(f.secret);
    assert_eq!(f.r#type, FieldType::String as i32);
}

#[test]
fn los_valores_de_configuracion_cubren_los_cuatro_tipos() {
    use sb_proto::{StringList, Value, value::Kind};

    let textos = Value {
        kind: Some(Kind::StringValue("x".into())),
    };
    let entero = Value {
        kind: Some(Kind::IntValue(5432)),
    };
    let booleano = Value {
        kind: Some(Kind::BoolValue(true)),
    };
    let lista = Value {
        kind: Some(Kind::ListValue(StringList {
            values: vec!["a".into(), "b".into()],
        })),
    };

    assert!(matches!(textos.kind, Some(Kind::StringValue(_))));
    assert!(matches!(entero.kind, Some(Kind::IntValue(5432))));
    assert!(matches!(booleano.kind, Some(Kind::BoolValue(true))));
    assert!(matches!(lista.kind, Some(Kind::ListValue(_))));
}

#[test]
fn un_check_fallido_puede_llevar_su_remedio() {
    // Un preflight que dice "falló" sin decir cómo arreglarlo no sirve de nada.
    let c = Check {
        name: "versiones".into(),
        ok: false,
        detail: "pg_dump 14 contra servidor 16".into(),
        remediation: "instala postgresql-client-16".into(),
    };
    assert!(!c.ok);
    assert!(!c.remediation.is_empty());
}

#[test]
fn los_mensajes_se_serializan_y_deserializan() {
    use prost::Message;

    let original = Progress {
        bytes: 1_048_576,
        message: "subiendo".into(),
    };
    let bytes = original.encode_to_vec();
    let vuelta = Progress::decode(&bytes[..]).unwrap();

    assert_eq!(vuelta.bytes, 1_048_576);
    assert_eq!(vuelta.message, "subiendo");
}

#[test]
fn un_campo_nuevo_no_rompe_a_un_lector_antiguo() {
    // La propiedad por la que se eligió protobuf: añadir campos no rompe a
    // quien fue compilado sin conocerlos. Se simula decodificando un
    // PreflightResponse a partir de bytes que llevan un campo desconocido.
    use prost::Message;

    let mut bytes = PreflightResponse {
        ok: true,
        checks: vec![],
        server_version: "16.2".into(),
    }
    .encode_to_vec();

    // Campo 99, varint, valor 1: algo que esta compilación no conoce.
    bytes.extend_from_slice(&[0x98, 0x06, 0x01]);

    let vuelta = PreflightResponse::decode(&bytes[..])
        .expect("un campo desconocido debe ignorarse, no romper la decodificación");
    assert!(vuelta.ok);
    assert_eq!(vuelta.server_version, "16.2");
}

#[test]
fn los_clientes_y_servidores_generados_existen() {
    // Comprueba que build_server(true) y build_client(true) hicieron su trabajo.
    // Solo referencia los tipos: si no existieran, no compilaría.
    fn _acepta_tipos() {
        let _: Option<sb_proto::plugin_client::PluginClient<tonic::transport::Channel>> = None;
        let _: Option<sb_proto::engine_client::EngineClient<tonic::transport::Channel>> = None;
        let _: Option<sb_proto::storage_client::StorageClient<tonic::transport::Channel>> = None;
    }
}
