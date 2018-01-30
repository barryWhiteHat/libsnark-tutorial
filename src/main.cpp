#include <libff/common/default_types/ec_pp.hpp>
#include <libsnark/common/default_types/r1cs_gg_ppzksnark_pp.hpp>
#include <libsnark/relations/constraint_satisfaction_problems/r1cs/examples/r1cs_examples.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_gg_ppzksnark/r1cs_gg_ppzksnark.hpp>

#include <libsnark/gadgetlib1/gadgets/basic_gadgets.hpp>

// default constraint system
#include <libsnark/gadgetlib2/gadget.hpp>
#include <libsnark/gadgetlib2/examples/simple_example.hpp>
#include <libsnark/gadgetlib2/examples/simple_example.hpp>
#include <libsnark/gadgetlib2/gadget.hpp>

//hash
#include <libff/common/profiling.hpp>
#include <libff/common/utils.hpp>
#include <libsnark/gadgetlib1/gadgets/hashes/sha256/sha256_gadget.hpp>



using namespace libsnark;

/**
 * The code below provides an example of all stages of running a R1CS GG-ppzkSNARK.
 *
 * Of course, in a real-life scenario, we would have three distinct entities,
 * mangled into one in the demonstration below. The three entities are as follows.
 * (1) The "generator", which runs the ppzkSNARK generator on input a given
 *     constraint system CS to create a proving and a verification key for CS.
 * (2) The "prover", which runs the ppzkSNARK prover on input the proving key,
 *     a primary input for CS, and an auxiliary input for CS.
 * (3) The "verifier", which runs the ppzkSNARK verifier on input the verification key,
 *     a primary input for CS, and a proof.
 */
template<typename ppT>
bool run_r1cs_gg_ppzksnark(const r1cs_example<libff::Fr<ppT> > &example)
{
    libff::print_header("R1CS GG-ppzkSNARK Generator");
    r1cs_gg_ppzksnark_keypair<ppT> keypair = r1cs_gg_ppzksnark_generator<ppT>(example.constraint_system);

    
    libff::print_header("Preprocess verification key");
    r1cs_gg_ppzksnark_processed_verification_key<ppT> pvk = r1cs_gg_ppzksnark_verifier_process_vk<ppT>(keypair.vk);

    libff::print_header("R1CS GG-ppzkSNARK Prover");
    r1cs_gg_ppzksnark_proof<ppT> proof = r1cs_gg_ppzksnark_prover<ppT>(keypair.pk, example.primary_input, example.auxiliary_input);
    printf("\n"); libff::print_indent(); libff::print_mem("after prover");

    libff::print_header("R1CS GG-ppzkSNARK Verifier");
    const bool ans = r1cs_gg_ppzksnark_verifier_strong_IC<ppT>(keypair.vk, example.primary_input, proof);
    printf("\n"); libff::print_indent(); libff::print_mem("after verifier");
    printf("* The verification result is: %s\n", (ans ? "PASS" : "FAIL"));

    libff::print_header("R1CS GG-ppzkSNARK Online Verifier");
    const bool ans2 = r1cs_gg_ppzksnark_online_verifier_strong_IC<ppT>(pvk, example.primary_input, proof);
    assert(ans == ans2);

    return ans;
}

template<typename FieldT>
void constraint_to_json(linear_combination<FieldT> constraints)
{
    std::cout << "{";
    uint count = 0;
    for (const linear_term<FieldT>& lt : constraints.terms)
    {
        if (count != 0) {
            std::cout << ",";
        }
        if (lt.coeff != 0 && lt.coeff != 1) {
            std::cout << '"' << lt.index << '"' << ":" << "-1";
        }
        else {
            std::cout << '"' << lt.index << '"' << ":" << lt.coeff;
        }
        count++;
    }
    std::cout << "}";
}

template<typename FieldT>
void r1cs_to_json(r1cs_constraint_system<FieldT> constraints)
{
    // output inputs, right now need to compile with debug flag so that the `variable_annotations`
    // exists. Having trouble setting that up so will leave for now.
    std::cout << "\n{\"variableMetaData\":[";
    for (size_t i = 0; i < constraints.num_variables(); ++i)
    {   
        std::cout << '"' << constraints.variable_annotations[i].c_str() << '"';
        if (i < constraints.num_variables() - 1) {
            std::cout << ", ";
        }
    }
    std::cout << "],\n";
    std::cout << "\"constraints\":[";

    for (size_t c = 0; c < constraints.num_constraints(); ++c)
    {
        std::cout << "[";
        constraint_to_json(constraints.constraints[c].a);
        std::cout << ",";
        constraint_to_json(constraints.constraints[c].b);
        std::cout << ",";
        constraint_to_json(constraints.constraints[c].c);
        if (c == constraints.num_constraints()-1 ) {
            std::cout << "]\n";
        } else {
            std::cout << "],\n";
        }
    }
    std::cout << "]}\n";
}


// sample code to do the same with gadgetlib2, this is not working yet because the 
// r1cs object is differnt so will have to reimplemnt r1cs_to_json
template<typename ppT>
void test_r1cs_gg_ppzksnark_gadgetlib2(size_t num_constraints, size_t input_size)
{
    using namespace gadgetlib2;
    initPublicParamsFromDefaultPp();
    ProtoboardPtr pb = Protoboard::create(R1P);
    VariableArray input(3, "input");
    Variable output("output");

    pb->addRank1Constraint(input[0], 5 + input[2], output,
                           "Constraint 1: input[0] * (5 + input[2]) == output");
    pb->addUnaryConstraint(input[1] - output,
                           "Constraint 2: input[1] - output == 0");
    pb->val(input[0]) = pb->val(input[1]) = pb->val(input[2]) = pb->val(output) = 42;
    //EXPECT_FALSE(pb->isSatisfied());
    // The constraint system is not satisfied. Now lets try values which satisfy the two equations
    // above:
    pb->val(input[0]) = 1;
    pb->val(input[1]) = pb->val(output) = 42; // input[1] - output == 0
    pb->val(input[2]) = 37; // 1 * (5 + 37) == 42
    //EXPECT_TRUE(pb->isSatisfied());
//    ConstraintSystem constraint_system = pb->constraintSystem();   

//    r1cs_example<libff::Fr<ppT> > example = generate_r1cs_example_with_binary_input<libff::Fr<ppT> >(num_constraints, input_size);

//    std::cout << num_constraints;
//    std::cout << input_size;
//    for (uint i=0; i<constraint_system.getNumberOfConstraints(); ++i) {
//        ::std::shared_ptr<Constraint> constraint = constraint_system.getConstraint(i);
//        Variable::set out = constraint->getUsedVariables();
//        auto iter = out.begin();
//        for (++iter; iter != out.end(); ++iter) {
//            std::cout << iter->asString()
//        }
//    }
//    r1cs_to_json(example.constraint_system);
//    const bool bit = run_r1cs_gg_ppzksnark<ppT>(example);
//    assert(bit);
}


template<typename FieldT>
void test_r1cs_gg_ppzksnark(size_t num_constraints, size_t input_size)
{
    const size_t new_num_constraints = num_constraints - 1;
    protoboard<libff::Fr<FieldT> > pb;
    // create variable A
    pb_variable_array<libff::Fr<FieldT> > A;
    // Create variable B
    pb_variable_array<libff::Fr<FieldT> > B;
    // Create variable res
    pb_variable<libff::Fr<FieldT> > res;

    res.allocate(pb, "res");
    A.allocate(pb, new_num_constraints, "A");
    B.allocate(pb, new_num_constraints, "B");

    // where s = [1, A , B ] 
    // compute_inner_product generates `a`, `b`, `c` so that s . a * s . b - s . c = 0
    // note a!=A && b!=B
    inner_product_gadget<libff::Fr<FieldT> > compute_inner_product(pb, A, B, res, "compute_inner_product");

    compute_inner_product.generate_r1cs_constraints();
    
    for (size_t i = 0; i < new_num_constraints; ++i)
    {
        // set all inputs to 1 except for the first and last.
        pb.val(A[i]) = 1;
        pb.val(B[i]) = 1;
    }
    // Gernerate a witness for these values.
    compute_inner_product.generate_r1cs_witness();
    // output r1cs as json
    r1cs_to_json(pb.get_constraint_system());
    // generate proving/verification key.
    // const bool bit = run_r1cs_gg_ppzksnark<ppT>(example);
    // assert(bit);
}


template<typename FieldT>
void hash_r1cs_gg_ppzksnark(size_t num_constraints, size_t input_size)
{
    protoboard<libff::Fr<FieldT>> pb;

    digest_variable<libff::Fr<FieldT>> left(pb, SHA256_digest_size, "left");
    digest_variable<libff::Fr<FieldT>> right(pb, SHA256_digest_size, "right");
    digest_variable<libff::Fr<FieldT>> output(pb, SHA256_digest_size, "output");

    sha256_two_to_one_hash_gadget<libff::Fr<FieldT>> f(pb, left, right, output, "f");
    f.generate_r1cs_constraints();
    printf("Number of constraints for sha256_two_to_one_hash_gadget: %zu\n", pb.num_constraints());

    const libff::bit_vector left_bv = libff::int_list_to_bits({0x426bc2d8, 0x4dc86782, 0x81e8957a, 0x409ec148, 0xe6cffbe8, 0xafe6ba4f, 0x9c6f1978, 0xdd7af7e9}, 32);
    const libff::bit_vector right_bv = libff::int_list_to_bits({0x038cce42, 0xabd366b8, 0x3ede7e00, 0x9130de53, 0x72cdf73d, 0xee825114, 0x8cb48d1b, 0x9af68ad0}, 32);
    const libff::bit_vector hash_bv = libff::int_list_to_bits({0xeffd0b7f, 0x1ccba116, 0x2ee816f7, 0x31c62b48, 0x59305141, 0x990e5c0a, 0xce40d33d, 0x0b1167d1}, 32);

    left.generate_r1cs_witness(left_bv);
    right.generate_r1cs_witness(right_bv);

    f.generate_r1cs_witness();
    output.generate_r1cs_witness(hash_bv);
    r1cs_to_json(pb.get_constraint_system());
    assert(pb.is_satisfied()); 
}

int main () {
//    default_r1cs_gg_ppzksnark_pp::init_public_params();
//    test_r1cs_gg_ppzksnark<default_r1cs_gg_ppzksnark_pp>(4, 1);
    libff::start_profiling();
    libff::default_ec_pp::init_public_params();
//    test_r1cs_gg_ppzksnark<default_r1cs_gg_ppzksnark_pp>(4, 1);
    hash_r1cs_gg_ppzksnark<default_r1cs_gg_ppzksnark_pp>(4, 1);
    return 0;
}
