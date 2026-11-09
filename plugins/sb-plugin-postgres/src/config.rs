//! The plugin's configuration schema and the resolved configuration.
//!
//! Everything `pg_dump`/`pg_restore` need lives here and nowhere else: the
//! source reads an already validated [`Config`] and never looks at the raw map
//! again.

use std::collections::HashMap;

use sb_plugin_sdk::Configured;
use sb_plugin_sdk::sb_proto::{Field, FieldType, Value, value::Kind};
use sb_plugin_sdk::tonic::Status;

pub const FIELD_HOST: &str = "host";
pub const FIELD_PORT: &str = "port";
pub const FIELD_DATABASE: &str = "database";
pub const FIELD_USER: &str = "user";
pub const FIELD_PASSWORD: &str = "password";
pub const FIELD_PG_DUMP_PATH: &str = "pg_dump_path";
pub const FIELD_PG_RESTORE_PATH: &str = "pg_restore_path";
pub const FIELD_PSQL_PATH: &str = "psql_path";
pub const FIELD_MAINTENANCE_DATABASE: &str = "maintenance_database";

/// `PostgreSQL`'s own default port.
pub const DEFAULT_PORT: i64 = 5432;
/// Bare binary names, resolved through `PATH` — the same convention
/// `sb-core` uses for a plugin's own executable and what any deployment that
/// installed `postgresql-client` already satisfies.
pub const DEFAULT_PG_DUMP_PATH: &str = "pg_dump";
pub const DEFAULT_PG_RESTORE_PATH: &str = "pg_restore";
/// Only a restore drill runs `psql`: it creates and drops the scratch database and
/// asks the check. Backups and plain restores never need it installed.
pub const DEFAULT_PSQL_PATH: &str = "psql";
/// The database a drill connects to in order to `CREATE`/`DROP` the scratch one:
/// it cannot be the scratch database itself, and `postgres` is the one every
/// server has.
pub const DEFAULT_MAINTENANCE_DATABASE: &str = "postgres";

/// The fields the plugin accepts, exactly as `Schema` publishes them.
///
/// Only `password` is secret: a host, a port, a database and a user name are
/// not credentials, and marking them secret would force the operator's TOML to
/// point every one of them at a file or an env var for no benefit.
#[must_use]
pub fn fields() -> Vec<Field> {
    vec![
        text(
            FIELD_HOST,
            true,
            false,
            "Host or address of the PostgreSQL server",
        ),
        Field {
            name: FIELD_PORT.into(),
            r#type: FieldType::Int as i32,
            required: false,
            secret: false,
            description: "Port the server listens on".into(),
            default_value: DEFAULT_PORT.to_string(),
        },
        text(FIELD_DATABASE, true, false, "Database to dump or restore"),
        text(
            FIELD_USER,
            true,
            false,
            "Role `pg_dump`/`pg_restore` connect as",
        ),
        text(
            FIELD_PASSWORD,
            false,
            true,
            "Password for `user`; omit it to rely on `.pgpass`, peer or trust authentication",
        ),
        Field {
            name: FIELD_PG_DUMP_PATH.into(),
            r#type: FieldType::Path as i32,
            required: false,
            secret: false,
            description: "Path to the `pg_dump` binary, if it is not the one on PATH".into(),
            default_value: DEFAULT_PG_DUMP_PATH.into(),
        },
        Field {
            name: FIELD_PG_RESTORE_PATH.into(),
            r#type: FieldType::Path as i32,
            required: false,
            secret: false,
            description: "Path to the `pg_restore` binary, if it is not the one on PATH".into(),
            default_value: DEFAULT_PG_RESTORE_PATH.into(),
        },
        Field {
            name: FIELD_PSQL_PATH.into(),
            r#type: FieldType::Path as i32,
            required: false,
            secret: false,
            description:
                "Path to the `psql` binary a restore drill uses, if it is not the one on PATH"
                    .into(),
            default_value: DEFAULT_PSQL_PATH.into(),
        },
        Field {
            name: FIELD_MAINTENANCE_DATABASE.into(),
            r#type: FieldType::String as i32,
            required: false,
            secret: false,
            description:
                "Database a restore drill connects to in order to create and drop its scratch \
                 database; `user` needs the CREATEDB privilege"
                    .into(),
            default_value: DEFAULT_MAINTENANCE_DATABASE.into(),
        },
    ]
}

fn text(name: &str, required: bool, secret: bool, description: &str) -> Field {
    Field {
        name: name.into(),
        r#type: FieldType::String as i32,
        required,
        secret,
        description: description.into(),
        default_value: String::new(),
    }
}

/// Validated configuration. It only exists if `Configure` succeeded.
///
/// `password` is private and only comes out through [`Config::password`], and
/// `Debug` is written by hand so it never leaves through that door either — the
/// same reasoning `sb-plugin-r2`'s `R2Config` documents for its keys.
#[derive(Clone)]
pub struct Config {
    pub host: String,
    pub port: i64,
    pub database: String,
    pub user: String,
    password: Option<String>,
    pub pg_dump_path: String,
    pub pg_restore_path: String,
    pub psql_path: String,
    pub maintenance_database: String,
}

impl Config {
    /// Validates the map that arrives in `ConfigureRequest`.
    ///
    /// # Errors
    /// [`Status::invalid_argument`] if `host`, `database` or `user` is missing,
    /// if a field has a type that does not belong to it, or if `port` is
    /// outside `1..=65535`.
    pub fn from_map(map: &HashMap<String, Value>) -> Result<Self, Status> {
        let host = required_string(map, FIELD_HOST)?;
        let database = required_string(map, FIELD_DATABASE)?;
        let user = required_string(map, FIELD_USER)?;
        let password = optional_string(map, FIELD_PASSWORD)?.map(str::to_string);

        let port = optional_int(map, FIELD_PORT)?.unwrap_or(DEFAULT_PORT);
        if !(1..=65535).contains(&port) {
            return Err(Status::invalid_argument(format!(
                "`{FIELD_PORT}` must be between 1 and 65535, it is {port}"
            )));
        }

        let pg_dump_path = optional_string(map, FIELD_PG_DUMP_PATH)?
            .unwrap_or(DEFAULT_PG_DUMP_PATH)
            .to_string();
        let pg_restore_path = optional_string(map, FIELD_PG_RESTORE_PATH)?
            .unwrap_or(DEFAULT_PG_RESTORE_PATH)
            .to_string();
        let psql_path = optional_string(map, FIELD_PSQL_PATH)?
            .unwrap_or(DEFAULT_PSQL_PATH)
            .to_string();
        let maintenance_database = optional_string(map, FIELD_MAINTENANCE_DATABASE)?
            .unwrap_or(DEFAULT_MAINTENANCE_DATABASE)
            .to_string();

        Ok(Self {
            host: host.to_string(),
            port,
            database: database.to_string(),
            user: user.to_string(),
            password,
            pg_dump_path,
            pg_restore_path,
            psql_path,
            maintenance_database,
        })
    }

    #[must_use]
    pub fn password(&self) -> Option<&str> {
        self.password.as_deref()
    }

    /// The same configuration aimed at another database on the same server.
    ///
    /// It is how a drill points `pg_restore` and `psql` at the scratch database
    /// without a second place that knows how to build their arguments.
    #[must_use]
    pub fn with_database(&self, database: &str) -> Self {
        Self {
            database: database.to_string(),
            ..self.clone()
        }
    }
}

impl std::fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("database", &self.database)
            .field("user", &self.user)
            .field("password", &self.password.as_ref().map(|_| "<redacted>"))
            .field("pg_dump_path", &self.pg_dump_path)
            .field("pg_restore_path", &self.pg_restore_path)
            .field("psql_path", &self.psql_path)
            .field("maintenance_database", &self.maintenance_database)
            .finish()
    }
}

fn required_string<'a>(
    map: &'a HashMap<String, Value>,
    field: &'static str,
) -> Result<&'a str, Status> {
    match optional_string(map, field)? {
        Some(s) => Ok(s),
        None => Err(Status::invalid_argument(format!(
            "the required field `{field}` is missing"
        ))),
    }
}

/// Reads an optional string. An empty string counts as absent: a field set to
/// `""` in the TOML is a field the user never got round to filling in.
fn optional_string<'a>(
    map: &'a HashMap<String, Value>,
    field: &'static str,
) -> Result<Option<&'a str>, Status> {
    match map.get(field).and_then(|v| v.kind.as_ref()) {
        None => Ok(None),
        Some(Kind::StringValue(s)) if s.is_empty() => Ok(None),
        Some(Kind::StringValue(s)) => Ok(Some(s)),
        Some(_) => Err(Status::invalid_argument(format!(
            "the field `{field}` must be a string"
        ))),
    }
}

/// Reads an optional integer. `None` means "it was not there", not "it was
/// there but wrong".
fn optional_int(map: &HashMap<String, Value>, field: &'static str) -> Result<Option<i64>, Status> {
    match map.get(field).and_then(|v| v.kind.as_ref()) {
        None => Ok(None),
        Some(Kind::IntValue(v)) => Ok(Some(*v)),
        Some(_) => Err(Status::invalid_argument(format!(
            "the field `{field}` must be an integer"
        ))),
    }
}

/// The configuration shared between the plugin's two services (`Plugin` and
/// `Source`). The SDK's [`Configured`] already writes the "no silent defaults
/// before `Configure`" rule once.
pub type State = Configured<Config>;

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use sb_plugin_sdk::sb_proto::{Value, value::Kind};
    use sb_plugin_sdk::tonic::Code;

    use super::{
        Config, DEFAULT_MAINTENANCE_DATABASE, DEFAULT_PG_DUMP_PATH, DEFAULT_PG_RESTORE_PATH,
        DEFAULT_PORT, DEFAULT_PSQL_PATH, FIELD_DATABASE, FIELD_HOST, FIELD_MAINTENANCE_DATABASE,
        FIELD_PASSWORD, FIELD_PG_DUMP_PATH, FIELD_PG_RESTORE_PATH, FIELD_PORT, FIELD_PSQL_PATH,
        FIELD_USER, fields,
    };

    fn string(s: &str) -> Value {
        Value {
            kind: Some(Kind::StringValue(s.into())),
        }
    }
    fn number(n: i64) -> Value {
        Value {
            kind: Some(Kind::IntValue(n)),
        }
    }

    fn base() -> HashMap<String, Value> {
        HashMap::from([
            (FIELD_HOST.to_string(), string("db.internal")),
            (FIELD_DATABASE.to_string(), string("app")),
            (FIELD_USER.to_string(), string("backup")),
        ])
    }

    #[test]
    fn the_schema_publishes_every_field_and_marks_only_the_password_as_secret() {
        let fields = fields();
        let names: Vec<&str> = fields.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(
            names,
            vec![
                FIELD_HOST,
                FIELD_PORT,
                FIELD_DATABASE,
                FIELD_USER,
                FIELD_PASSWORD,
                FIELD_PG_DUMP_PATH,
                FIELD_PG_RESTORE_PATH,
                FIELD_PSQL_PATH,
                FIELD_MAINTENANCE_DATABASE,
            ]
        );
        for f in &fields {
            assert_eq!(f.secret, f.name == FIELD_PASSWORD, "`{}`", f.name);
        }
    }

    #[test]
    fn host_database_and_user_are_required_and_the_rest_are_not() {
        let fields = fields();
        for name in [FIELD_HOST, FIELD_DATABASE, FIELD_USER] {
            assert!(fields.iter().find(|f| f.name == name).unwrap().required);
        }
        for name in [
            FIELD_PORT,
            FIELD_PASSWORD,
            FIELD_PG_DUMP_PATH,
            FIELD_PG_RESTORE_PATH,
            FIELD_PSQL_PATH,
            FIELD_MAINTENANCE_DATABASE,
        ] {
            assert!(!fields.iter().find(|f| f.name == name).unwrap().required);
        }
    }

    #[test]
    fn every_field_has_a_description() {
        for f in fields() {
            assert!(!f.description.is_empty(), "`{}` has no description", f.name);
        }
    }

    #[test]
    fn without_host_the_configuration_is_rejected() {
        let mut m = base();
        m.remove(FIELD_HOST);
        let e = Config::from_map(&m).unwrap_err();
        assert_eq!(e.code(), Code::InvalidArgument);
        assert!(e.message().contains(FIELD_HOST));
    }

    #[test]
    fn without_database_the_configuration_is_rejected() {
        let mut m = base();
        m.remove(FIELD_DATABASE);
        assert_eq!(
            Config::from_map(&m).unwrap_err().code(),
            Code::InvalidArgument
        );
    }

    #[test]
    fn without_user_the_configuration_is_rejected() {
        let mut m = base();
        m.remove(FIELD_USER);
        assert_eq!(
            Config::from_map(&m).unwrap_err().code(),
            Code::InvalidArgument
        );
    }

    #[test]
    fn the_port_defaults_to_5432() {
        let c = Config::from_map(&base()).unwrap();
        assert_eq!(c.port, DEFAULT_PORT);
        assert_eq!(DEFAULT_PORT, 5432);
    }

    #[test]
    fn an_explicit_port_overrides_the_default() {
        let mut m = base();
        m.insert(FIELD_PORT.to_string(), number(6543));
        assert_eq!(Config::from_map(&m).unwrap().port, 6543);
    }

    #[test]
    fn a_port_out_of_range_is_rejected() {
        for bad in [0_i64, 70_000] {
            let mut m = base();
            m.insert(FIELD_PORT.to_string(), number(bad));
            assert_eq!(
                Config::from_map(&m).unwrap_err().code(),
                Code::InvalidArgument,
                "port {bad}"
            );
        }
    }

    #[test]
    fn the_password_is_optional_and_absent_by_default() {
        let c = Config::from_map(&base()).unwrap();
        assert_eq!(c.password(), None);
    }

    #[test]
    fn an_explicit_password_is_kept() {
        let mut m = base();
        m.insert(FIELD_PASSWORD.to_string(), string("hunter2"));
        assert_eq!(Config::from_map(&m).unwrap().password(), Some("hunter2"));
    }

    #[test]
    fn the_configuration_does_not_expose_the_password_when_printed() {
        let mut m = base();
        m.insert(FIELD_PASSWORD.to_string(), string("hunter2"));
        let c = Config::from_map(&m).unwrap();
        assert!(!format!("{c:?}").contains("hunter2"));
    }

    #[test]
    fn the_dump_and_restore_paths_default_to_the_bare_binary_names() {
        let c = Config::from_map(&base()).unwrap();
        assert_eq!(c.pg_dump_path, DEFAULT_PG_DUMP_PATH);
        assert_eq!(c.pg_restore_path, DEFAULT_PG_RESTORE_PATH);
    }

    #[test]
    fn explicit_dump_and_restore_paths_override_the_default() {
        let mut m = base();
        m.insert(
            FIELD_PG_DUMP_PATH.to_string(),
            string("/opt/pg16/bin/pg_dump"),
        );
        m.insert(
            FIELD_PG_RESTORE_PATH.to_string(),
            string("/opt/pg16/bin/pg_restore"),
        );
        let c = Config::from_map(&m).unwrap();
        assert_eq!(c.pg_dump_path, "/opt/pg16/bin/pg_dump");
        assert_eq!(c.pg_restore_path, "/opt/pg16/bin/pg_restore");
    }

    #[test]
    fn a_wrong_type_is_rejected_instead_of_ignored() {
        let mut m = base();
        m.insert(FIELD_PORT.to_string(), string("five-four-three-two"));
        assert_eq!(
            Config::from_map(&m).unwrap_err().code(),
            Code::InvalidArgument
        );
    }

    #[test]
    fn the_drill_fields_default_to_psql_and_the_postgres_database() {
        let c = Config::from_map(&base()).unwrap();
        assert_eq!(c.psql_path, DEFAULT_PSQL_PATH);
        assert_eq!(c.maintenance_database, DEFAULT_MAINTENANCE_DATABASE);
        assert_eq!(DEFAULT_MAINTENANCE_DATABASE, "postgres");
    }

    #[test]
    fn explicit_drill_fields_override_the_defaults() {
        let mut m = base();
        m.insert(FIELD_PSQL_PATH.to_string(), string("/opt/pg16/bin/psql"));
        m.insert(FIELD_MAINTENANCE_DATABASE.to_string(), string("template1"));
        let c = Config::from_map(&m).unwrap();
        assert_eq!(c.psql_path, "/opt/pg16/bin/psql");
        assert_eq!(c.maintenance_database, "template1");
    }

    #[test]
    fn aiming_at_another_database_changes_only_the_database() {
        let mut m = base();
        m.insert(FIELD_PASSWORD.to_string(), string("hunter2"));
        let original = Config::from_map(&m).unwrap();

        let scratch = original.with_database("drill_1");
        assert_eq!(scratch.database, "drill_1");
        assert_eq!(scratch.host, original.host);
        assert_eq!(scratch.user, original.user);
        assert_eq!(scratch.password(), Some("hunter2"));
        // And the original is untouched: the backup still goes to its own database.
        assert_eq!(original.database, "app");
    }
}
