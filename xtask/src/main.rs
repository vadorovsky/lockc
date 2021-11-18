use eyre::Result;
use structopt::StructOpt;

mod bintar;
mod build_ebpf;
mod codegen;
mod install;

#[derive(StructOpt)]
pub(crate) struct Options {
    #[structopt(subcommand)]
    command: Command,
}

#[derive(StructOpt)]
enum Command {
    Bintar(bintar::Options),
    BuildEbpf(build_ebpf::Options),
    Codegen,
    Install(install::Options),
}

fn main() -> Result<()> {
    let opts = Options::from_args();

    use Command::*;
    match opts.command {
        Bintar(opts) => {
            bintar::BinTar::new(opts).do_bin_tar()?;
        }
        BuildEbpf(opts) => build_ebpf::build_ebpf(opts)?,
        Codegen => codegen::generate()?,
        Install(opts) => {
            install::Installer::new(opts).do_install()?;
        }
    };

    Ok(())
}
