use axiom_eth::Field;
use axiom_eth::keccak::{KeccakChip};
use clap::Parser;
use ethers_core::utils::hex::FromHex;
use halo2_base::QuantumCell::Constant;
use halo2_base::gates::{GateInstructions, RangeChip, RangeInstructions};
use halo2_base::utils::ScalarField;
use halo2_base::{AssignedValue, Context};
use halo2_scaffold::scaffold::cmd::Cli;
use halo2_scaffold::scaffold::run;
use serde::{Deserialize, Serialize};

pub const NUM_FIELDS: usize = 16;
pub const MAX_TOT_LEN: usize = 1024;
pub const LEAD_BITS: usize = 4;

#[derive(Clone, Debug)]
pub struct MerkleTrace<F: ScalarField> {
    pub root: Vec<AssignedValue<F>>,
    pub directions: Vec<AssignedValue<F>>,
    pub proof: Vec<Vec<AssignedValue<F>>>,
    pub val: Vec<AssignedValue<F>>,
    pub depth: AssignedValue<F>,
}



#[derive(Clone, Debug)]
pub struct CircuitInputAssigned<F: ScalarField> {
    pub root: Vec<AssignedValue<F>>,
    pub header: DataPacketAssigned<F>,
    pub directions: Vec<AssignedValue<F>>,
    pub proof: Vec<Vec<AssignedValue<F>>>,
    pub fields: DataPacketAssigned<F>,
    pub depth: AssignedValue<F>,
    pub author: WordAssigned<F>,
    pub name: WordAssigned<F>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DataPacket {
    concat: String,
    lens: Vec<usize>,
}
#[derive(Clone, Debug)]
pub struct DataPacketAssigned<F: ScalarField> {
    concat: Vec<AssignedValue<F>>,
    lens:Vec<AssignedValue<F>>,
    concat_len: AssignedValue<F>,
    cnt: AssignedValue<F>
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Word {
    bytes: String,
}
#[derive(Clone, Debug)]
pub struct WordAssigned<F: ScalarField> {
    bytes: Vec<AssignedValue<F>>,
    len: AssignedValue<F>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]

pub struct CircuitInput {
    pub root: String,
    pub header: DataPacket,
    pub directions: Vec<u8>,
    pub merkle_proof: Vec<String>,
    pub fields: DataPacket,
    pub max_depth: usize,
    pub author: Word,
    pub name: Word,
}

pub fn assign_vec<F: ScalarField>(ctx: &mut Context<F>, vals: Vec<u8>, max_len: usize) -> Vec<AssignedValue<F>> {
    let mut newvals = vals.clone();
    newvals.resize(max_len, 0);
    newvals.into_iter().map(|v| {
        ctx.load_witness(F::from(v as u64))
    }).collect()
}

impl CircuitInput {
    pub fn assign<F: ScalarField>(self, ctx: &mut Context<F>, max_depth: usize) -> CircuitInputAssigned<F> {
        let depth = self.merkle_proof.len();
        let zero_node = "0000000000000000000000000000000000000000000000000000000000000000".to_string();
        let mut nodes = self.merkle_proof.clone();
        nodes.resize(max_depth, zero_node);
        assert!(depth <= max_depth);
        let root = Vec::from_hex(self.root).unwrap();
        let root = assign_vec(ctx, root, 32);
        let proof = nodes.into_iter().map(|node| {
            let node = Vec::from_hex(node).unwrap();
            assign_vec(ctx, node, 32)
        }).collect();
        let mut directions = self.directions.clone();
        directions.resize(max_depth, 0);
        let directions = assign_vec(ctx, directions, max_depth);
        let depth = ctx.load_witness(F::from(depth as u64));
        let fields = self.fields.assign(ctx);
        let header = self.header.assign(ctx);
        let author = self.author.assign(ctx);
        let name = self.name.assign(ctx);
        CircuitInputAssigned {
            root,
            header,
            directions,
            proof,
            fields,
            depth,
            author,
            name,
        }
    }
}

impl DataPacket {
    pub fn assign<F: ScalarField>(self, ctx: &mut Context<F>) -> DataPacketAssigned<F> {
        let concat = self.concat.as_bytes().to_vec();
        let cnt = ctx.load_witness(F::from(self.lens.len() as u64));
        let concat_len = ctx.load_witness(F::from(concat.len() as u64));
        let mut vals = self.lens.clone();
        assert!(vals.len() <= NUM_FIELDS);
        assert!(concat.len() <= MAX_TOT_LEN);
        vals.resize(NUM_FIELDS, 0);
        let mut decomp_val: Vec<u8> = Vec::new();
        for val in vals {
            let first = val / 256;
            let second = val % 256;
            decomp_val.push((first as u8).try_into().unwrap());
            decomp_val.push((second as u8).try_into().unwrap());
        }
        let lens = assign_vec(ctx, decomp_val, 64);
        let concat = assign_vec(ctx, concat, 1024);
        DataPacketAssigned { concat, lens, concat_len, cnt }
    }
}

impl Word {
    pub fn assign<F: ScalarField>(self, ctx: &mut Context<F>) -> WordAssigned<F> {
        let bytes = self.bytes.as_bytes().to_vec();
        let len = bytes.len();
        assert!(len <= 64);
        let len = ctx.load_witness(F::from(len as u64));
        let bytes = assign_vec(ctx, bytes, 64);
        WordAssigned { bytes, len }
    }
}

pub fn calc_hash_root<F: Field>(ctx: &mut Context<F>, range: &RangeChip<F>, keccak: &mut KeccakChip<F>, data: DataPacketAssigned<F>) -> Vec<AssignedValue<F>> {
    let hash_idx = keccak.keccak_var_len(ctx, range, data.concat, None, data.concat_len, 0);
    let mut data_hash = keccak.var_len_queries[hash_idx].output_assigned.to_vec().clone();
    let double_cnt = range.gate().add(ctx, data.cnt, data.cnt);
    let hash_idx = keccak.keccak_var_len(ctx, range, data.lens, None, double_cnt, 0);
    let mut len_hash = keccak.var_len_queries[hash_idx].output_assigned.to_vec().clone();
    data_hash.append(&mut len_hash);
    let hash_idx = keccak.keccak_fixed_len(ctx, range.gate(), data_hash, None);
    keccak.fixed_len_queries[hash_idx].output_assigned.to_vec().clone()
}

pub fn calc_words_root<F: Field>(ctx: &mut Context<F>, range: &RangeChip<F>, keccak: &mut KeccakChip<F>, w1: WordAssigned<F>, w2: WordAssigned<F>) -> Vec<AssignedValue<F>> {
    let hash_idx = keccak.keccak_var_len(ctx, range, w1.bytes, None, w1.len, 0);
    let mut first_hash = keccak.var_len_queries[hash_idx].output_assigned.to_vec().clone();
    let hash_idx = keccak.keccak_var_len(ctx, range, w2.bytes, None, w2.len, 0);
    let mut second_hash = keccak.var_len_queries[hash_idx].output_assigned.to_vec().clone();
    first_hash.append(&mut second_hash);
    let hash_idx = keccak.keccak_fixed_len(ctx, range.gate(), first_hash, None);
    keccak.fixed_len_queries[hash_idx].output_assigned.to_vec().clone()
}

pub fn verify_merkle_proof<F: Field>(
    ctx: &mut Context<F>,
    range: &RangeChip<F>,
    keccak: &mut KeccakChip<F>,
    proof: Vec<Vec<AssignedValue<F>>>,
    val: &Vec<AssignedValue<F>>,
    directions: Vec<AssignedValue<F>>,
    root: Vec<AssignedValue<F>>,
    depth: AssignedValue<F>,
    max_depth: usize,
) ->  MerkleTrace<F> {
    range.check_less_than_safe(ctx, depth, max_depth as u64 + 1);
    let mut cum_roots = vec![assign_vec(ctx, vec![], 32)];
    let depth_minus_one = range.gate().sub(ctx, depth, Constant(F::one()));
    let depth_minus_one_indicator = range.gate().idx_to_indicator(ctx, depth_minus_one, max_depth);
    let zero = ctx.load_zero();
    for i in 0..max_depth {
        let idx = max_depth - i - 1;
        range.check_less_than_safe(ctx, directions[idx], 2);
        let mut child = vec![zero; 32];
        for j in 0..32 {
            child[j] = range.gate().select(ctx, val[j], cum_roots[i][j], depth_minus_one_indicator[idx]);
        }
        let mut other_child = proof[idx].clone();
        let mut child_clone = child.clone();
        child.append(&mut other_child.clone());
        other_child.append(&mut child_clone);
        let left_idx = keccak.keccak_fixed_len(ctx, range.gate(), child, None);
        let right_idx = keccak.keccak_fixed_len(ctx, range.gate(), other_child, None);
        let left_root = &keccak.fixed_len_queries[left_idx].output_assigned;
        let right_root = &keccak.fixed_len_queries[right_idx].output_assigned;
        let sel_root: Vec<AssignedValue<F>> = left_root.into_iter().zip(right_root.into_iter()).map(|(left, right)| {
            range.gate().select(ctx, *right, *left, directions[idx])
        }).collect();
        cum_roots.push(sel_root);
    }
    for i in 0..32 {
        ctx.constrain_equal(&cum_roots[max_depth][i], &root[i]);
    }
    MerkleTrace { root, directions, proof, val: val.to_vec(), depth }
}


fn some_algorithm_in_zk<F: Field>(
    ctx: &mut Context<F>,
    input: CircuitInput,
    make_public: &mut Vec<AssignedValue<F>>,
) {
    //let x = F::from_str_vartime(&input.x).expect("deserialize field element should not fail");
    // `Context` can roughly be thought of as a single-threaded execution trace of a program we want to ZK prove. We do some post-processing on `Context` to optimally divide the execution trace into multiple columns in a PLONKish arithmetization
    // More advanced usage with multi-threaded witness generation is possible, but we do not explain it here
    let max_depth = input.max_depth;
    let mut keccak: KeccakChip<F> = KeccakChip::default();
    let input = input.assign(ctx, max_depth);
    let range = RangeChip::default(15);
    let val = &calc_hash_root(ctx, &range, &mut keccak, input.fields);
    let trace = verify_merkle_proof(ctx, &range, &mut keccak, input.proof, val, input.directions, input.root.clone(), input.depth, max_depth);
    let zero = ctx.load_zero();
    let bad_depth = range.is_less_than_safe(ctx, input.depth, LEAD_BITS as u64);
    ctx.constrain_equal(&bad_depth, &zero);
    for i in 0..LEAD_BITS {
        ctx.constrain_equal(&trace.directions[i], &zero);
    }
    // let last_dir = range.gate().select_by_indicator(ctx, trace.directions, depth_minus_one_indicator);
    // ctx.constrain_equal(&last_dir, &zero);
    let first_node = calc_hash_root(ctx, &range, &mut keccak, input.header);
    for i in 0..32 {
        ctx.constrain_equal(&first_node[i], &trace.proof[0][i]);
    }
    let second_node = calc_words_root(ctx, &range, &mut keccak, input.author, input.name);
    for i in 0..32 {
        ctx.constrain_equal(&second_node[i], &trace.proof[1][i]);
    }
    let fourth_node = &trace.proof[3];
    let mut eval = ctx.load_zero();
    let _256 = ctx.load_constant(F::from(256));
    for i in 0..32{
        eval = range.gate().mul_add(ctx, _256, eval, fourth_node[i]);
    }
    let list_depth = max_depth - LEAD_BITS;
    let list_depth_minus_one = range.gate().sub(ctx, input.depth, Constant(F::from(LEAD_BITS as u64 + 1)));
    let list_depth_minus_one_indicator = range.gate().idx_to_indicator(ctx, list_depth_minus_one, list_depth);
    let mut list_indicator = vec![zero; list_depth];
    list_indicator[list_depth - 1] = list_depth_minus_one_indicator[list_depth - 1];
    for i in 1..list_depth {
        list_indicator[list_depth - i - 1] = range.gate().add(ctx, list_indicator[list_depth - i], list_depth_minus_one_indicator[list_depth - i - 1]);
    }
    let mut idx = zero;
    for i in 0..list_depth {
        let mut new_val = range.gate().add(ctx, idx, trace.directions[LEAD_BITS + i]);
        new_val = range.gate().mul(ctx, new_val, list_indicator[i]);
        idx = range.gate().add(ctx, new_val, idx);
    }
    range.check_less_than(ctx, idx, eval, max_depth);
    let mut hlower = ctx.load_constant(F::from(0));
    let base = ctx.load_constant(F::from(256));
    for i in 0..16 {
        hlower = range.gate().mul(ctx, hlower, base);
        hlower = range.gate().add(ctx, hlower, first_node[16 + i]);
    }
    let mut hupper = ctx.load_constant(F::from(0));
    for i in 0..16 {
        hupper = range.gate().mul(ctx, hupper, base);
        hupper = range.gate().add(ctx, hupper, first_node[i]);
    }
    let mut flower = ctx.load_constant(F::from(0));
    for i in 0..16 {
        flower = range.gate().mul(ctx, flower, base);
        flower = range.gate().add(ctx, flower, val[16 + i]);
    }
    let mut fupper = ctx.load_constant(F::from(0));
    for i in 0..16 {
        fupper = range.gate().mul(ctx, fupper, base);
        fupper = range.gate().add(ctx, fupper, val[i]);
    }
    let mut rlower = ctx.load_constant(F::from(0));
    for i in 0..16 {
        rlower = range.gate().mul(ctx, rlower, base);
        rlower = range.gate().add(ctx, rlower, input.root[16 + i]);
    }
    let mut rupper = ctx.load_constant(F::from(0));
    for i in 0..16 {
        rupper = range.gate().mul(ctx, rupper, base);
        rupper = range.gate().add(ctx, rupper, input.root[i]);
    }
    make_public.push(rupper);
    make_public.push(rlower);
    make_public.push(hupper);
    make_public.push(hlower);
    make_public.push(fupper);
    make_public.push(flower);
    // create a Range chip that contains methods for basic arithmetic operations
}

fn main() {
    env_logger::init();

    let args = Cli::parse();

    // run different zk commands based on the command line arguments
    run(some_algorithm_in_zk, args);
}
