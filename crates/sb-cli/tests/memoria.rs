// Igual que en el resto de los tests del workspace: aquí un `unwrap` es lo que
// se quiere, que el test explote justo donde falló. Estos ayudantes son
// funciones libres de un fichero `tests/`, así que el permiso de `clippy.toml`
// —que solo alcanza a `#[test]` y `#[cfg(test)]`— no llega hasta ellos y hay
// que darlo a nivel de fichero.
#![allow(clippy::unwrap_used, clippy::expect_used)]

//! ¿Es verdad que la memoria no depende del tamaño del backup?
//!
//! El diseño entero de `ShieldBackups` se apoya en una promesa: respaldar una
//! base de 400 GB consume la misma RAM que respaldar una de 2 GB, porque nada
//! se acumula —el volcado va del motor al destino atravesando zstd y age en
//! streaming—. Es la promesa que permite prometer un contenedor con límite
//! bajo. Este fichero la mide en vez de creérsela.
//!
//! # Cómo se mide
//!
//! Sin `unsafe`, que el workspace prohíbe: `getrusage` obligaría a `libc`, así
//! que se lee `/proc`. Se lanza `shieldbk` como hijo y un hilo muestrea cada
//! 25 ms el `/proc/<pid>/status` del núcleo **y el de todos sus descendientes**,
//! que son los procesos de plugin. Medir solo el núcleo no valdría: si el
//! núcleo va constante pero el plugin acumula, la promesa está igual de rota.
//!
//! De cada proceso se leen dos cifras:
//!
//! - `VmRSS`, la residencia **instantánea**. Muestrearla puede perderse el
//!   pico si ocurre entre dos muestras.
//! - `VmHWM`, el pico **histórico** que el propio núcleo de Linux lleva. Nunca
//!   baja, así que quedarse con el máximo de las lecturas da el pico real
//!   siempre que se haya leído al menos una vez cerca del final.
//!
//! Se informan las dos y se comparan: si difieren mucho, el muestreo se está
//! perdiendo el pico y hay que fiarse de `VmHWM`. Las aserciones de tamaño usan
//! `VmHWM`, que es la cifra conservadora; la de `--jobs` usa el máximo de
//! `núcleo + plugins` **dentro de una misma muestra**, porque ahí los plugins
//! se turnan y sumar picos históricos que nunca coincidieron inflaría la base.
//!
//! # Qué NO cubre esto
//!
//! Se mide contra `sb-plugin-mock`, cuyo destino escribe el artefacto de una
//! vez sobre un fichero. **El troceador multipart de `sb-plugin-r2` no entra
//! aquí**, y es el mayor consumidor de RAM del sistema: su techo previsto es
//! `part_size × concurrency`, 64 MiB × 4 = 256 MiB por defecto
//! (`plugins/sb-plugin-r2/src/put.rs`). Estas cifras miden el núcleo y el
//! camino de datos; el presupuesto de un contenedor que suba a R2 tiene que
//! sumarles ese techo.
//!
//! # Cómo se ejecutan
//!
//! Todos van marcados `#[ignore]`: mueven gigabytes por el disco y no pueden
//! correr en cada push. Los cuatro juntos tardan unos 21 s en release —menos de
//! lo que sugiere el volumen, porque el pipeline va a ~400 MiB/s—, pero en
//! debug pasan de varios minutos.
//!
//! ```text
//! cargo test --release --test memoria -- --ignored --nocapture
//! ```
//!
//! **En release.** El perfil de debug asigna de otra forma —sin inlining, con
//! los buffers de zstd y age sin optimizar— y sus cifras no representan lo que
//! corre en producción. `--nocapture` es lo que hace que las cifras se vean;
//! sin él el test dice «ok» y no enseña nada, que es justo lo contrario de lo
//! que se quiere de estos tests.
//!
//! # Línea base medida
//!
//! Medido el 2026-08-21 en `x86_64`, Linux 6.17, 16 núcleos, perfil `release`,
//! `rustc` del `rust-toolchain.toml`. Cifras en MiB: «núcleo» y «plugins» son
//! `VmHWM`; «a la vez» es el máximo de `núcleo + plugins` en una misma muestra,
//! que es lo que tiene que caber en el límite del contenedor.
//!
//! | Escenario                       | Núcleo | Plugins | A la vez |
//! |---------------------------------|-------:|--------:|---------:|
//! | backup 64 MiB                   |   15,2 |    14,6 |     29,8 |
//! | backup 256 MiB                  |   15,1 |    14,8 |     29,9 |
//! | backup 1 GiB                    |   15,3 |    14,8 |     30,0 |
//! | backup 2 GiB                    |   15,3 |    15,2 |     30,4 |
//! | verify 64 MiB                   |    9,8 |     7,5 |     17,2 |
//! | verify 1 GiB                    |    9,8 |     7,6 |     17,4 |
//! | restore 64 MiB                  |   12,2 |    15,0 |     27,3 |
//! | restore 1 GiB                   |   12,3 |    15,1 |     27,4 |
//! | 3 targets × 256 MiB, `--jobs 1` |   15,6 |    15,3 |     30,8 |
//! | 3 targets × 256 MiB, `--jobs 3` |   26,0 |    44,7 |     70,7 |
//!
//! Entre ejecuciones estas cifras se mueven ±0,5 MiB. Los umbrales de los
//! tests están puestos muy por encima de ese ruido a propósito: lo que tienen
//! que detectar es una acumulación, no una fluctuación.
//!
//! Lo que dicen estas cifras:
//!
//! - **La promesa se cumple.** De 256 MiB a 2 GiB —ocho veces más datos— la
//!   memoria pasó de 29,9 a 30,4 MiB: un 1,7 % más, ruido. Y de 64 MiB a 1 GiB
//!   —dieciséis veces más— `backup`, `verify` y `restore` se movieron un 1 %.
//!   Un backup de 2 GiB cabe de sobra en un contenedor de 512 MiB: usa el 6 %.
//! - **El pico no depende del tamaño porque no aparece durante el flujo.** Se
//!   alcanza al arrancar —runtime de tokio, buffers de zstd y age, TLS del
//!   canal— y de ahí no se mueve: por eso `VmRSS` muestreado y `VmHWM`
//!   coinciden al 0,0 % en las diez mediciones.
//! - **`--jobs` cuesta unos 20 MiB por trabajo simultáneo** sobre una base de
//!   ~31 MiB: tres a la vez son 70,7 MiB, un 2,30× que se queda por debajo del
//!   ×3 que el paralelismo justificaría, porque el núcleo comparte runtime y
//!   solo se duplican los procesos de plugin. Regla para dimensionar:
//!   `31 MiB + 20 MiB × jobs`, más el techo del destino (ver arriba).

mod comun;

use std::collections::HashMap;
use std::fmt::Write as _;
use std::io::Read;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use comun::{Banco, json_de};

use sb_crypto::Identity;

/// Cada cuánto se mira `/proc`. Más fino no aporta —`VmHWM` no se pierde el
/// pico— y más grueso haría inútil la comparación entre las dos medidas.
const INTERVALO: Duration = Duration::from_millis(25);

/// Un MiB en bytes: la unidad en la que se le pide tamaño al motor mock.
const MIB: u64 = 1024 * 1024;
const GIB: u64 = 1024 * MIB;

/// Un MiB en KiB: la unidad en la que `/proc` da la memoria, y por tanto la
/// unidad de todos los umbrales de este fichero.
const MIB_EN_KIB: u64 = 1024;

// ---------------------------------------------------------------------------
// Medición
// ---------------------------------------------------------------------------

/// El pico de memoria de una ejecución completa: el núcleo y sus plugins.
///
/// Todas las cifras en KiB, que es como las da `/proc/<pid>/status`.
#[derive(Debug, Default, Clone, Copy)]
struct Pico {
    /// Máximo `VmRSS` del núcleo visto por el muestreo.
    nucleo_rss: u64,
    /// Máximo `VmHWM` del núcleo. Es el pico real.
    nucleo_hwm: u64,
    /// Máxima **suma** de los `VmRSS` de los plugins en un mismo instante.
    plugins_rss: u64,
    /// Suma de los `VmHWM` de cada plugin visto. Cota superior: si dos plugins
    /// no coincidieron en el tiempo, suma dos picos que nunca fueron a la vez.
    plugins_hwm: u64,
    /// El máximo de `núcleo + plugins` **en la misma muestra**: lo que de
    /// verdad hay residente a la vez, y por tanto lo que tiene que caber en el
    /// límite del contenedor.
    simultaneo_rss: u64,
    /// Cuántos plugins distintos se vieron. Sirve para saber si el muestreo
    /// llegó a verlos: cero plugins es una medición inválida, no un éxito.
    plugins_vistos: u64,
    muestras: u64,
    duracion: Duration,
}

impl Pico {
    /// Cota superior de lo que consume el sistema entero.
    ///
    /// Suma el `VmHWM` del núcleo y el de **cada** plugin que se llegó a ver.
    /// Cuando los plugins viven a la vez —un solo target— es la cifra exacta.
    /// Cuando se turnan —varios targets con `--jobs 1`— suma picos que nunca
    /// coincidieron y sale de más; para eso está `simultaneo_rss`.
    fn total_hwm(self) -> u64 {
        self.nucleo_hwm + self.plugins_hwm
    }
}

impl std::fmt::Display for Pico {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "núcleo {} (RSS muestreado {}) · plugins {} en {} procesos (RSS muestreado {}) \
             · residente a la vez {} · cota {} · {:.1} s, {} muestras",
            mib(self.nucleo_hwm),
            mib(self.nucleo_rss),
            mib(self.plugins_hwm),
            self.plugins_vistos,
            mib(self.plugins_rss),
            mib(self.simultaneo_rss),
            mib(self.total_hwm()),
            self.duracion.as_secs_f64(),
            self.muestras,
        )
    }
}

/// KiB a un texto en MiB, que es la unidad en la que se piensa un contenedor.
fn mib(kib: u64) -> String {
    #[allow(clippy::cast_precision_loss)] // Para imprimir, no para comparar.
    let m = kib as f64 / 1024.0;
    format!("{m:.1} MiB")
}

/// `VmRSS` y `VmHWM` de un proceso, en KiB.
///
/// `None` si el proceso ya no está: cuando el hijo muere su `/proc/<pid>`
/// desaparece, y eso es el final normal del muestreo, no un error.
fn memoria_de(pid: u32) -> Option<(u64, u64)> {
    let texto = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    let mut rss = None;
    let mut hwm = None;
    for linea in texto.lines() {
        if let Some(resto) = linea.strip_prefix("VmRSS:") {
            rss = kib_de(resto);
        } else if let Some(resto) = linea.strip_prefix("VmHWM:") {
            hwm = kib_de(resto);
        }
    }
    Some((rss?, hwm?))
}

/// `       12345 kB` → `12345`.
fn kib_de(resto: &str) -> Option<u64> {
    resto.split_whitespace().next()?.parse().ok()
}

/// Los hijos directos de un proceso, según `/proc/<pid>/task/<tid>/children`.
///
/// Hay que recorrer los hilos porque cada uno lleva su propia lista: el núcleo
/// es un runtime de tokio y no siempre lanza el plugin desde el hilo principal.
fn hijos(pid: u32) -> Vec<u32> {
    let mut encontrados = Vec::new();
    let Ok(tareas) = std::fs::read_dir(format!("/proc/{pid}/task")) else {
        return encontrados;
    };
    for tarea in tareas.flatten() {
        if let Ok(texto) = std::fs::read_to_string(tarea.path().join("children")) {
            encontrados.extend(
                texto
                    .split_whitespace()
                    .filter_map(|p| p.parse::<u32>().ok()),
            );
        }
    }
    encontrados
}

/// Todos los descendientes de `raiz`. Los plugins son hijos directos, pero se
/// baja el árbol entero por si algún día uno de ellos lanza algo.
fn descendientes(raiz: u32) -> Vec<u32> {
    let mut vistos = Vec::new();
    let mut pendientes = hijos(raiz);
    while let Some(pid) = pendientes.pop() {
        if vistos.contains(&pid) {
            continue;
        }
        pendientes.extend(hijos(pid));
        vistos.push(pid);
    }
    vistos
}

/// El bucle de muestreo. Sale en cuanto `terminado` se enciende, que es justo
/// después de que el padre haya recogido al hijo: seguir leyendo `/proc`
/// después de eso mediría el pid de otro.
fn muestrear(raiz: u32, terminado: &AtomicBool) -> Pico {
    let inicio = Instant::now();
    let mut pico = Pico::default();
    let mut hwm_por_plugin: HashMap<u32, u64> = HashMap::new();

    while !terminado.load(Ordering::Relaxed) {
        if let Some((rss, hwm)) = memoria_de(raiz) {
            pico.nucleo_rss = pico.nucleo_rss.max(rss);
            pico.nucleo_hwm = pico.nucleo_hwm.max(hwm);
        }
        let mut suma_rss = 0;
        for plugin in descendientes(raiz) {
            if let Some((rss, hwm)) = memoria_de(plugin) {
                suma_rss += rss;
                let anotado = hwm_por_plugin.entry(plugin).or_default();
                *anotado = (*anotado).max(hwm);
            }
        }
        pico.plugins_rss = pico.plugins_rss.max(suma_rss);
        // El total simultáneo se calcula **dentro** de la muestra: el máximo
        // del núcleo y el máximo de los plugins pueden no haber ocurrido a la
        // vez, y sumarlos por separado inventaría un instante que no existió.
        let nucleo_ahora = memoria_de(raiz).map_or(0, |(rss, _)| rss);
        pico.simultaneo_rss = pico.simultaneo_rss.max(nucleo_ahora + suma_rss);
        pico.muestras += 1;
        std::thread::sleep(INTERVALO);
    }

    pico.plugins_hwm = hwm_por_plugin.values().sum();
    pico.plugins_vistos = hwm_por_plugin.len() as u64;
    pico.duracion = inicio.elapsed();
    pico
}

/// Lo que dejó una ejecución medida.
struct Salida {
    pico: Pico,
    exito: bool,
    stdout: String,
    stderr: String,
}

impl Salida {
    /// Falla el test con la salida completa si el comando no fue bien. Un test
    /// de memoria que midiera un `shieldbk` que se murió al arrancar daría una
    /// cifra estupenda y una mentira.
    fn exigir(self, que: &str) -> Self {
        assert!(
            self.exito,
            "{que} falló:\nstdout: {}\nstderr: {}",
            self.stdout, self.stderr
        );
        assert!(
            self.pico.nucleo_hwm > 0,
            "{que}: no se llegó a leer /proc del núcleo; la medición no vale"
        );
        assert!(
            self.pico.plugins_vistos > 0,
            "{que}: no se vio ningún proceso de plugin; la medición solo cubre \
             el núcleo y no sirve para lo que se quiere demostrar"
        );
        self
    }
}

/// Ejecuta `orden` midiendo el pico de memoria de todo su árbol de procesos.
fn medir(orden: &mut Command) -> Salida {
    let mut hijo = orden
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let pid = hijo.id();

    // Las tuberías se vacían desde hilos aparte: si se dejaran llenar, el hijo
    // se bloquearía escribiendo y el test se colgaría para siempre.
    let mut salida = hijo.stdout.take().unwrap();
    let mut errores = hijo.stderr.take().unwrap();
    let lector_salida = std::thread::spawn(move || {
        let mut texto = String::new();
        let _ = salida.read_to_string(&mut texto);
        texto
    });
    let lector_errores = std::thread::spawn(move || {
        let mut texto = String::new();
        let _ = errores.read_to_string(&mut texto);
        texto
    });

    let terminado = Arc::new(AtomicBool::new(false));
    let muestreador = {
        let terminado = Arc::clone(&terminado);
        std::thread::spawn(move || muestrear(pid, &terminado))
    };

    // `wait` mata la espera y recoge al hijo: sin esto quedaría un zombi.
    let estado = hijo.wait().unwrap();
    terminado.store(true, Ordering::Relaxed);

    Salida {
        pico: muestreador.join().unwrap(),
        exito: estado.success(),
        stdout: lector_salida.join().unwrap(),
        stderr: lector_errores.join().unwrap(),
    }
}

// ---------------------------------------------------------------------------
// El banco de pruebas
// ---------------------------------------------------------------------------

/// Un entorno listo para medir: mock instalado, registrado y configurado.
struct Escenario {
    banco: Banco,
    config: PathBuf,
    clave: PathBuf,
}

impl Escenario {
    /// `targets` son pares `(nombre, bytes que emite el motor)`.
    fn nuevo(targets: &[(&str, u64)]) -> Self {
        let banco = Banco::nuevo();
        banco.instalar_mock();

        let identidad = Identity::generate();
        let clave = banco.ruta("clave.age");
        std::fs::write(
            &clave,
            format!(
                "# created: 2026-08-21T00:00:00Z\n# public key: {}\n{}\n",
                identidad.to_recipient(),
                identidad.to_secret_string().expose()
            ),
        )
        .unwrap();

        let mut toml = format!(
            "[plugins]\ndir = {dir:?}\nlockfile = {lock:?}\n",
            dir = banco.dir_plugins().to_string_lossy(),
            lock = banco.lockfile().to_string_lossy(),
        );
        for (nombre, tamano) in targets {
            // Cada target con su directorio: así el `restore.bin` de uno no
            // pisa el de otro y el disco de cada uno se puede mirar aparte.
            let datos = banco.dir_datos().join(nombre);
            std::fs::create_dir_all(&datos).unwrap();
            write!(
                toml,
                "\n[[target]]\nname = \"{nombre}\"\nengine = \"mock\"\nstorage = \"mock\"\n\
                 recipient = \"{recipient}\"\n\
                 \n[target.engine_config]\ndir = {datos:?}\nseed = 7\nsize = {tamano}\n\
                 \n[target.storage_config]\ndir = {datos:?}\n",
                recipient = identidad.to_recipient(),
                datos = datos.to_string_lossy(),
            )
            .unwrap();
        }
        let config = banco.config(&toml);

        let lock = Command::new(env!("CARGO_BIN_EXE_shieldbk"))
            .env("HOME", banco.raiz.path())
            .env_remove("RUST_LOG")
            .args(["--config", &config.to_string_lossy(), "plugin", "lock"])
            .output()
            .unwrap();
        assert!(
            lock.status.success(),
            "plugin lock falló: {}",
            String::from_utf8_lossy(&lock.stderr)
        );

        Self {
            banco,
            config,
            clave,
        }
    }

    /// Un `shieldbk` con el entorno aislado y `--config` ya puesto.
    fn orden(&self, argumentos: &[&str]) -> Command {
        let mut orden = Command::new(env!("CARGO_BIN_EXE_shieldbk"));
        orden
            .env("HOME", self.banco.raiz.path())
            .env_remove("RUST_LOG")
            .args(["--config", &self.config.to_string_lossy()])
            .args(argumentos);
        orden
    }

    /// Un backup medido. Va siempre en `--format json` para poder sacar la
    /// clave del artefacto de la salida y encadenar `verify` y `restore`.
    fn backup(&self, argumentos: &[&str]) -> Salida {
        let mut todos = vec!["--format", "json"];
        todos.extend_from_slice(argumentos);
        medir(&mut self.orden(&todos)).exigir("backup")
    }

    /// La clave del artefacto que dejó un backup en `--format json`.
    fn clave_de(salida: &Salida) -> String {
        json_de(salida.stdout.as_bytes())["targets"][0]["artifact_key"]
            .as_str()
            .unwrap()
            .to_string()
    }

    /// Comprueba que el backup movió de verdad los bytes que dice.
    ///
    /// Sin esto, un test de memoria pasaría con una configuración rota que no
    /// respaldó nada: cero bytes también consumen memoria constante. Los datos
    /// del mock son incompresibles a propósito, así que el artefacto cifrado
    /// tiene que pesar prácticamente lo mismo que el volcado.
    fn exigir_que_movio(&self, target: &str, clave: &str, bytes: u64) {
        let ruta = self.banco.dir_datos().join(target).join(clave);
        let peso = std::fs::metadata(&ruta)
            .unwrap_or_else(|e| panic!("no está el artefacto {}: {e}", ruta.display()))
            .len();
        assert!(
            peso >= bytes / 10 * 9,
            "el artefacto de `{target}` pesa {peso} B y se volcaron {bytes} B: \
             la medición no atravesó los datos que dice"
        );
    }

    /// Deja el disco como estaba: 2 GiB de artefactos por prueba se acumulan
    /// rápido si no se borran entre fases.
    fn limpiar(&self, target: &str) {
        let _ = std::fs::remove_dir_all(self.banco.dir_datos().join(target));
        std::fs::create_dir_all(self.banco.dir_datos().join(target)).unwrap();
    }
}

/// Comprueba que muestreo y pico histórico cuentan la misma historia.
///
/// Si el muestreo se queda muy por debajo del `VmHWM`, es que el pico ocurrió
/// entre dos lecturas de 25 ms. No es un fallo del programa medido, pero hay
/// que decirlo, porque significa que la cifra instantánea que se imprime no es
/// la que manda.
fn contrastar(etiqueta: &str, pico: Pico) {
    #[allow(clippy::cast_precision_loss)]
    let desvio = if pico.nucleo_hwm == 0 {
        0.0
    } else {
        1.0 - (pico.nucleo_rss as f64 / pico.nucleo_hwm as f64)
    };
    println!(
        "  [{etiqueta}] muestreo VmRSS vs VmHWM del núcleo: {} vs {} ({:.1}% por debajo)",
        mib(pico.nucleo_rss),
        mib(pico.nucleo_hwm),
        desvio * 100.0,
    );
}

/// La razón entre dos picos, para imprimirla y para compararla.
#[allow(clippy::cast_precision_loss)]
fn razon(grande: u64, pequeno: u64) -> f64 {
    if pequeno == 0 {
        return f64::INFINITY;
    }
    grande as f64 / pequeno as f64
}

// ---------------------------------------------------------------------------
// Los tests
// ---------------------------------------------------------------------------

#[test]
#[ignore = "mueve gigabytes por el disco: cargo test --release --test memoria -- --ignored --nocapture"]
fn la_memoria_no_crece_con_el_tamano_del_backup() {
    // El test que decide si el diseño es lo que dice ser. Ocho veces más datos
    // por el mismo tubo: si el tubo no acumula, la cifra no se mueve.
    let escenario = Escenario::nuevo(&[("pequeno", 256 * MIB), ("grande", 2 * GIB)]);

    let salida = escenario.backup(&["backup", "pequeno"]);
    let pequeno = salida.pico;
    escenario.exigir_que_movio("pequeno", &Escenario::clave_de(&salida), 256 * MIB);
    println!("\n256 MiB → {pequeno}");
    contrastar("256 MiB", pequeno);
    escenario.limpiar("pequeno");

    let salida = escenario.backup(&["backup", "grande"]);
    let grande = salida.pico;
    escenario.exigir_que_movio("grande", &Escenario::clave_de(&salida), 2 * GIB);
    println!("  2 GiB → {grande}");
    contrastar("2 GiB", grande);
    escenario.limpiar("grande");

    let crecimiento = razon(grande.total_hwm(), pequeno.total_hwm());
    println!(
        "\n  8× datos → {crecimiento:.2}× memoria ({} → {})\n",
        mib(pequeno.total_hwm()),
        mib(grande.total_hwm()),
    );

    assert!(
        crecimiento <= 1.5,
        "ocho veces más datos costaron {crecimiento:.2}× de memoria \
         ({} con 256 MiB, {} con 2 GiB). La promesa de memoria constante no se \
         cumple: hay acumulación en el pipeline.",
        mib(pequeno.total_hwm()),
        mib(grande.total_hwm()),
    );
}

#[test]
#[ignore = "mueve gigabytes por el disco: cargo test --release --test memoria -- --ignored --nocapture"]
fn un_backup_grande_cabe_en_un_limite_razonable() {
    // La cifra que hace creíble un `--memory=512m` en el contenedor.
    const LIMITE: u64 = 512 * MIB_EN_KIB;

    let escenario = Escenario::nuevo(&[("grande", 2 * GIB)]);
    let salida = escenario.backup(&["backup", "grande"]);
    let pico = salida.pico;
    escenario.exigir_que_movio("grande", &Escenario::clave_de(&salida), 2 * GIB);
    println!("\n2 GiB en un solo backup → {pico}\n");

    assert!(
        pico.nucleo_hwm <= LIMITE,
        "el núcleo llegó a {} respaldando 2 GiB; el presupuesto es {}",
        mib(pico.nucleo_hwm),
        mib(LIMITE),
    );
    assert!(
        pico.total_hwm() <= LIMITE,
        "el sistema entero (núcleo + plugins) llegó a {}; el presupuesto es {}",
        mib(pico.total_hwm()),
        mib(LIMITE),
    );
}

#[test]
#[ignore = "mueve gigabytes por el disco: cargo test --release --test memoria -- --ignored --nocapture"]
fn el_ciclo_completo_tampoco_acumula() {
    // `backup` es el camino que más se mira, pero `verify` lee el artefacto
    // entero y `restore` lo descifra y lo descomprime entero. Si alguno de los
    // dos acumulase, la promesa valdría para hacer copias y no para usarlas,
    // que es lo único que justifica hacerlas.
    const LIMITE: u64 = 512 * MIB_EN_KIB;

    // Dos tamaños por fase: con uno solo se sabría el consumo, pero no si
    // crece, que es la pregunta.
    let escenario = Escenario::nuevo(&[("chico", 64 * MIB), ("gordo", GIB)]);

    let mut ciclos = Vec::new();
    for (target, etiqueta) in [("chico", "64 MiB"), ("gordo", "1 GiB")] {
        let salida = escenario.backup(&["backup", target]);
        let backup = salida.pico;
        let clave = Escenario::clave_de(&salida);
        println!("\n[{etiqueta}] backup  → {backup}");

        let verify = medir(&mut escenario.orden(&["verify", target, &clave]))
            .exigir("verify")
            .pico;
        println!("[{etiqueta}] verify  → {verify}");

        let restore = medir(&mut escenario.orden(&[
            "restore",
            target,
            &clave,
            "--identity",
            &escenario.clave.to_string_lossy(),
        ]))
        .exigir("restore")
        .pico;
        println!("[{etiqueta}] restore → {restore}");
        contrastar(etiqueta, restore);

        ciclos.push([("backup", backup), ("verify", verify), ("restore", restore)]);
        escenario.limpiar(target);
    }
    let [chicos, gordos] = [ciclos[0], ciclos[1]];

    println!();
    for ((fase, chico), (_, gordo)) in chicos.iter().zip(gordos.iter()) {
        println!(
            "  {fase:<8} 64 MiB → 1 GiB (16× datos): {} → {} = {:.2}×",
            mib(chico.total_hwm()),
            mib(gordo.total_hwm()),
            razon(gordo.total_hwm(), chico.total_hwm()),
        );
    }
    println!();

    for ((fase, chico), (_, gordo)) in chicos.iter().zip(gordos.iter()) {
        let crecimiento = razon(gordo.total_hwm(), chico.total_hwm());
        assert!(
            crecimiento <= 1.5,
            "`{fase}` costó {crecimiento:.2}× más memoria con 16× más datos \
             ({} → {}): esa fase acumula.",
            mib(chico.total_hwm()),
            mib(gordo.total_hwm()),
        );
        assert!(
            gordo.total_hwm() <= LIMITE,
            "`{fase}` con 1 GiB llegó a {}; el presupuesto es {}",
            mib(gordo.total_hwm()),
            mib(LIMITE),
        );
    }
}

#[test]
#[ignore = "mueve gigabytes por el disco: cargo test --release --test memoria -- --ignored --nocapture"]
fn la_concurrencia_multiplica_la_memoria_de_forma_previsible() {
    // Quien dimensione un contenedor necesita esto y no otra cosa: cuánto
    // cuesta subir `--jobs`. Que el coste sea previsible importa más que que
    // sea bajo; lo que no puede ser es que explote.
    const TAMANO: u64 = 256 * MIB;
    const JOBS: u64 = 3;

    let escenario = Escenario::nuevo(&[("uno", TAMANO), ("dos", TAMANO), ("tres", TAMANO)]);

    // Sin nombre de target se respaldan los tres, que es lo que hace que
    // `--jobs` tenga algo que paralelizar.
    let secuencial = escenario.backup(&["--jobs", "1", "backup"]).pico;
    println!("\n3 targets × 256 MiB, --jobs 1 → {secuencial}");
    contrastar("--jobs 1", secuencial);
    for t in ["uno", "dos", "tres"] {
        escenario.limpiar(t);
    }

    let paralelo = escenario.backup(&["--jobs", "3", "backup"]).pico;
    println!("3 targets × 256 MiB, --jobs 3 → {paralelo}");
    contrastar("--jobs 3", paralelo);
    for t in ["uno", "dos", "tres"] {
        escenario.limpiar(t);
    }

    // Aquí **no** vale `total_hwm`: con `--jobs 1` los seis plugins se turnan,
    // nunca están vivos a la vez, y sumar sus seis picos históricos inflaría la
    // base contra la que se compara —haciendo que el paralelismo pareciera
    // gratis—. La pregunta es cuánta RAM hay residente en el mismo instante, y
    // eso es `simultaneo_rss`.
    let factor = razon(paralelo.simultaneo_rss, secuencial.simultaneo_rss);
    let factor_nucleo = razon(paralelo.nucleo_hwm, secuencial.nucleo_hwm);
    let por_trabajo = paralelo
        .simultaneo_rss
        .saturating_sub(secuencial.simultaneo_rss)
        / (JOBS - 1);
    println!(
        "\n  --jobs 1 → --jobs 3: residente a la vez {} → {} = {factor:.2}× \
         (VmHWM del núcleo {factor_nucleo:.2}×)",
        mib(secuencial.simultaneo_rss),
        mib(paralelo.simultaneo_rss),
    );
    println!(
        "  Para dimensionar: ~{} de base más ~{} por cada trabajo simultáneo de más.\n",
        mib(secuencial.simultaneo_rss),
        mib(por_trabajo),
    );

    #[allow(clippy::cast_precision_loss)]
    let techo = JOBS as f64;
    assert!(
        factor <= techo,
        "con --jobs 3 la memoria residente se multiplicó por {factor:.2} \
         ({} → {}), más de lo que el paralelismo justifica (×{techo:.0}). El \
         coste de `--jobs` no es proporcional: algo se acumula por trabajo.",
        mib(secuencial.simultaneo_rss),
        mib(paralelo.simultaneo_rss),
    );
    // Y por si el paralelismo se quedara en nada: con tres a la vez tiene que
    // haber más residente que con uno, o el test no estaría midiendo `--jobs`.
    assert!(
        factor > 1.0,
        "con --jobs 3 la memoria residente no subió respecto a --jobs 1 \
         ({} → {}): o no hubo paralelismo real o el muestreo no lo vio",
        mib(secuencial.simultaneo_rss),
        mib(paralelo.simultaneo_rss),
    );
}
