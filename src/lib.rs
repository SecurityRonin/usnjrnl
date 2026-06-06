//! NTFS USN Journal parser with full path reconstruction via journal rewind.
//!
//! Implements the CyberCX "Rewind" algorithm for complete path resolution,
//! even when MFT entries have been reallocated. Also provides direct binary
//! parsing of $UsnJrnl:$J (V2/V3/V4), $MFT correlation, $MFTMirr comparison,
//! and $LogFile gap detection.

/// Enable `log` macro argument evaluation for the whole test binary.
///
/// `warn!`/`debug!`/etc. skip evaluating their arguments unless the global max
/// level permits the record, so under test (no logger installed → level `Off`)
/// the format arguments — real code on real lines — never run. We install a
/// discarding sink logger at `Trace` once, before any test. Claiming the global
/// logger also makes the stray `env_logger::try_init()` calls in tests fail
/// silently (they are `let _ =`-ignored) instead of resetting the level back to
/// `Error`, so the diagnostic branches stay exercised.
#[cfg(test)]
mod test_log_setup {
    struct Sink;
    impl log::Log for Sink {
        fn enabled(&self, _: &log::Metadata) -> bool {
            true
        }
        fn log(&self, _: &log::Record) {}
        fn flush(&self) {}
    }
    static SINK: Sink = Sink;

    #[ctor::ctor]
    fn init() {
        let _ = log::set_logger(&SINK);
        log::set_max_level(log::LevelFilter::Trace);
    }

    #[test]
    fn sink_logger_implements_all_trait_methods() {
        use log::Log;
        let meta = log::MetadataBuilder::new().level(log::Level::Trace).build();
        assert!(SINK.enabled(&meta));
        SINK.log(&log::Record::builder().args(format_args!("x")).build());
        SINK.flush();
    }
}

pub mod analysis;
pub mod correlation;
pub mod image;
pub mod logfile;
pub mod mft;
pub mod mftmirr;
pub mod monitor;
pub mod output;
pub mod refs;
pub mod rewind;
pub mod rules;
pub mod triage;
pub mod usn;
