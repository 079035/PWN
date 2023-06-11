module solution::baby_otter_solution {
    use sui::tx_context::TxContext;
    use challenge::baby_otter_challenge;

    public entry fun solve(status: &mut baby_otter_challenge::Status, ctx: &mut TxContext) {

    let str = x"4834434b";
        baby_otter_challenge::request_ownership(status,str,ctx);        
    }
}