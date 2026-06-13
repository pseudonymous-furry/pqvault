// THIS IS A PRE-RELEASE STILL. DO NOT USE THIS IN PRODUCTION! -w-

mod app;
mod crypto;
mod models;
mod storage;
mod tui;
mod util;

use anyhow::Result;

fn main() -> Result<()> {
    util::disable_core_dumps();
    app::run_app()
}
