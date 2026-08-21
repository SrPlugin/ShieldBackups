//! Las operaciones que el usuario pide: backup, restore y verify.
//!
//! Cada una compone las mismas tres piezas —dos plugins vivos, dos canales de
//! datos y el pipeline de `sb-crypto`— y ninguna de esas piezas conoce a las
//! otras. Aquí es donde se juntan, y por tanto donde vive lo único que no cabe
//! en ninguna de ellas: **el orden en que se hablan**.

pub mod backup;
