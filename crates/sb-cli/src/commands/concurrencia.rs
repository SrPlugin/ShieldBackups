//! Cuántos targets se tocan a la vez.
//!
//! `--jobs` no es una opción de rendimiento: es un freno. Un backup lanza un
//! volcado contra un servidor que además está atendiendo a usuarios, y tres
//! targets en paralelo son tres volcados compitiendo por el mismo disco y la
//! misma caché. Por eso el valor por defecto es uno y por eso el límite se
//! aplica siempre, incluso cuando alguien pide más trabajos de los que hay
//! targets.
//!
//! El otro motivo de que esto viva aparte es que la política tiene que ser la
//! misma en `backup` y en `doctor`: si cada uno se montara su propio bucle,
//! subir el freno en uno y olvidarlo en el otro sería cuestión de tiempo.

use std::sync::Arc;

use tokio::sync::Semaphore;

/// Ejecuta `tarea` sobre cada elemento con como mucho `jobs` a la vez.
///
/// Los resultados salen **en el orden de entrada**, no en el de terminación:
/// un informe cuyo orden dependiera de qué base de datos fue más rápida hoy
/// sería imposible de comparar con el de ayer.
///
/// Ningún elemento aborta a los demás. Es la misma razón que en `doctor`: quien
/// respalda diez targets quiere saber cuáles fallaron, no cuál falló primero.
pub async fn por_lotes<T, R, F, Fut>(elementos: Vec<T>, jobs: usize, tarea: F) -> Vec<R>
where
    F: Fn(T) -> Fut,
    Fut: Future<Output = R>,
{
    // Cero permisos dejaría el proceso esperando uno que no llega nunca. Quien
    // escribe `--jobs 0` quería «pocos», no «ninguno».
    let permisos = Arc::new(Semaphore::new(jobs.max(1)));

    let pendientes = elementos.into_iter().map(|elemento| {
        let permisos = Arc::clone(&permisos);
        let futura = tarea(elemento);
        async move {
            // El permiso se pide **antes** de que la tarea avance un solo
            // paso, y se suelta al terminar porque el guardia muere aquí.
            // `acquire_owned` solo falla si el semáforo se cierra, y este vive
            // exactamente lo que este bucle.
            let _permiso = permisos.acquire_owned().await;
            futura.await
        }
    });

    futures_util::future::join_all(pendientes).await
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    #[tokio::test]
    async fn los_resultados_salen_en_el_orden_de_entrada() {
        // Aunque el trabajo termine desordenado: un informe cuyo orden dependa
        // de qué target fue más rápido hoy no se puede comparar con el de ayer.
        let salida = por_lotes(vec![3_u64, 1, 2], 3, |n| async move {
            tokio::time::sleep(std::time::Duration::from_millis(n * 20)).await;
            n
        })
        .await;
        assert_eq!(salida, vec![3, 1, 2]);
    }

    #[tokio::test]
    async fn nunca_hay_mas_de_jobs_a_la_vez() {
        // Es la razón de ser del módulo: dos volcados simultáneos contra el
        // mismo servidor es exactamente lo que hay que evitar.
        let vivos = Arc::new(AtomicUsize::new(0));
        let maximo = Arc::new(AtomicUsize::new(0));

        por_lotes((0..8).collect(), 2, |_| {
            let vivos = Arc::clone(&vivos);
            let maximo = Arc::clone(&maximo);
            async move {
                let ahora = vivos.fetch_add(1, Ordering::SeqCst) + 1;
                maximo.fetch_max(ahora, Ordering::SeqCst);
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                vivos.fetch_sub(1, Ordering::SeqCst);
            }
        })
        .await;

        let pico = maximo.load(Ordering::SeqCst);
        assert!(pico <= 2, "se pasaron {pico} a la vez con --jobs 2");
        assert!(
            pico >= 2,
            "con --jobs 2 y ocho tareas debería haber paralelismo"
        );
    }

    #[tokio::test]
    async fn jobs_cero_se_trata_como_uno() {
        let salida = por_lotes(vec![1, 2], 0, |n| async move { n * 2 }).await;
        assert_eq!(salida, vec![2, 4]);
    }

    #[tokio::test]
    async fn con_un_solo_trabajo_las_tareas_no_se_solapan() {
        // El valor por defecto, y el que de verdad protege al servidor.
        let vivos = Arc::new(AtomicUsize::new(0));
        let maximo = Arc::new(AtomicUsize::new(0));

        por_lotes((0..4).collect(), 1, |_| {
            let vivos = Arc::clone(&vivos);
            let maximo = Arc::clone(&maximo);
            async move {
                let ahora = vivos.fetch_add(1, Ordering::SeqCst) + 1;
                maximo.fetch_max(ahora, Ordering::SeqCst);
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
                vivos.fetch_sub(1, Ordering::SeqCst);
            }
        })
        .await;

        assert_eq!(maximo.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn una_lista_vacia_no_hace_nada() {
        let salida: Vec<u8> = por_lotes(Vec::new(), 4, |n: u8| async move { n }).await;
        assert!(salida.is_empty());
    }
}
