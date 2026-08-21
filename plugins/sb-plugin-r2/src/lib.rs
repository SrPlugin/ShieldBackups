//! `sb-plugin-r2`: el destino de backups sobre Cloudflare R2.
//!
//! R2 habla el protocolo de S3, y de ahí que el plugin use el SDK de AWS. Lo
//! que no es de S3 —la región `auto`, el endpoint de cuenta, los checksums y
//! el tamaño uniforme de las partes— está aislado en [`cliente`] y [`config`],
//! con el motivo escrito al lado.
//!
//! ## Por qué esto es una librería y no solo un binario
//!
//! El binario `sb-plugin-r2` es cuatro líneas y toda la lógica vive aquí. La
//! razón es que los módulos hay que poder ejercitarlos **contra un servidor de
//! verdad**: `tests/integracion.rs` levanta un `MinIO` en Docker, monta un
//! [`cliente::Contexto`] apuntando a él y llama a [`put::subir`],
//! [`admin::listar`] y compañía. Con los módulos privados dentro del binario,
//! esas pruebas solo podrían hablar por gRPC y no podrían mirar el bucket por
//! dentro —las partes de un multipart a medio subir, por ejemplo, que es
//! justamente lo que hay que comprobar—.

pub mod admin;
pub mod canal;
pub mod claves;
pub mod cliente;
pub mod config;
pub mod get;
pub mod plugin;
pub mod put;
pub mod storage;
pub mod trozos;
