//! Extract NTFS artifacts from an E01 image to a directory.
//! Usage: cargo run --features image --example extract -- <image.E01> <output_dir>

fn main() {
    #[cfg(feature = "image")]
    {
        use std::path::Path;
        let args: Vec<String> = std::env::args().collect();
        if args.len() != 3 {
            eprintln!("Usage: {} <image.E01> <output_dir>", args[0]);
            std::process::exit(1);
        }
        let artifacts =
            usnjrnl_forensic::image::extract_artifacts(Path::new(&args[1]), Path::new(&args[2]))
                .expect("extraction failed");
        eprintln!("$MFT:        {}", artifacts.mft.display());
        eprintln!("$UsnJrnl:$J: {}", artifacts.usnjrnl.display());
        eprintln!("$LogFile:    {}", artifacts.logfile.display());
        eprintln!("$MFTMirr:    {}", artifacts.mftmirr.display());
    }

    #[cfg(not(feature = "image"))]
    {
        eprintln!("This example requires the 'image' feature:");
        eprintln!("  cargo run --features image --example extract -- <image.E01> <output_dir>");
        std::process::exit(1);
    }
}
