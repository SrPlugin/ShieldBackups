//! Las operaciones que el usuario pide: backup, restore y verify.
//!
//! Cada una compone las mismas tres piezas —dos plugins vivos, dos canales de
//! datos y el pipeline de `sb-crypto`— y ninguna de esas piezas conoce a las
//! otras. Aquí es donde se juntan, y por tanto donde vive lo único que no cabe
//! en ninguna de ellas: **el orden en que se hablan**.
//!
//! Ese orden es lo único propio de cada operación, y por eso la mecánica que
//! las tres comparten —crear el canal, pedir el RPC, esperar la conexión con
//! plazo, drenar el progreso y traducir los fallos— está aparte, en [`canal`]:
//! si viviera aquí, este módulo dejaría de ser el mapa de qué operaciones hay.

pub mod backup;
pub mod canal;
pub mod restore;
pub mod verify;

// El error es de las tres operaciones, no de una: la mecánica que lo produce
// —plazos, canales de datos, flujo de progreso— es común y vive en `canal`.
pub use canal::BackupError;
