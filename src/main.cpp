#include <libff/common/default_types/ec_pp.hpp>
#include <libsnark/common/default_types/r1cs_gg_ppzksnark_pp.hpp>
#include <libsnark/relations/constraint_satisfaction_problems/r1cs/examples/r1cs_examples.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_gg_ppzksnark/r1cs_gg_ppzksnark.hpp>

#include <libsnark/gadgetlib1/gadgets/basic_gadgets.hpp>


#include <libsnark/gadgetlib2/gadget.hpp>
#include <libsnark/gadgetlib2/examples/simple_example.hpp>
#include <libsnark/gadgetlib2/examples/simple_example.hpp>
#include <libsnark/gadgetlib2/gadget.hpp>

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
void r1cs_to_json(r1cs_constraint_system<FieldT> constraints)
{


// output inputs, right now need to compile with debug flag so that the `variable_annotations`
// exists. Having trouble setting that up so will leave for now.
    std::cout << " s = [    ";
    for (size_t i = 0; i < constraints.num_variables(); ++i)
    {   
        std::cout << constraints.variable_annotations[i].c_str();
        if (i < constraints.num_variables() - 1) {
            std::cout << ", ";
        }
        //values[i].as_bigint().print_hex();
    }
    std::cout << "]\n";

    // output a

    size_t last = -1;
    std::cout << " a = [ \n";
    for (size_t c = 0; c < constraints.num_constraints(); ++c)
    {
        for (const linear_term<FieldT>& lt : constraints.constraints[c].a.terms)
        {
            if (last == c) {  
                std::cout << ",";
            }
            else {
                std::cout << "    [";
            }
            std::cout << "("<< c << ", " << lt.index << ")=" << lt.coeff;
            last = c;        
        }
        std::cout << "]";


    }
    std::cout << "\n]\n";
    // output b
    std::cout << " b = [ \n";

    last = -1;
    for (size_t c = 0; c < constraints.num_constraints(); ++c)
    {   
        for (const linear_term<FieldT>& lt : constraints.constraints[c].b.terms)
        {   

            if (last == c) {  
                std::cout << ",";
            }
            else {
                std::cout << "    [";
            }
            std::cout << "("<< c << ", " << lt.index << ")=" << lt.coeff;
            last = c;        
        }
        std::cout << "]";

    }
    std::cout << "\n]\n";
    // output c
    std::cout << " c = [";
    last = -1;
    for (size_t c = 0; c < constraints.num_constraints(); ++c)
    {   
        std::cout << "\n";
        for (const linear_term<FieldT>& lt : constraints.constraints[c].c.terms)
        {   
            if (last == c) { 
                std::cout << ",";
            }
            else {
                std::cout << "    [";
            }
            std::cout << "("<< c << ", " << lt.index << ")=" << lt.coeff;
            last = c; 
        }
        std::cout << "]";
    }
    std::cout << "\n]\n";
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


template<typename ppT>
void test_r1cs_gg_ppzksnark(size_t num_constraints, size_t input_size)
{
    const size_t new_num_constraints = num_constraints - 1;
    protoboard<libff::Fr<ppT> > pb;
    // create variable A
    pb_variable_array<libff::Fr<ppT> > A;
    // Create variable B
    pb_variable_array<libff::Fr<ppT> > B;
    // Create variable res
    pb_variable<libff::Fr<ppT> > res;

    res.allocate(pb, "res");
    A.allocate(pb, new_num_constraints, "A");
    B.allocate(pb, new_num_constraints, "B");

    // where s = [1, A , B ] 
    // compute_inner_product generates `a`, `b`, `c` so that s . a * s . b - s . c = 0
    // note a!=A && b!=B
    inner_product_gadget<libff::Fr<ppT> > compute_inner_product(pb, A, B, res, "compute_inner_product");

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

int main () {
    default_r1cs_gg_ppzksnark_pp::init_public_params();
    test_r1cs_gg_ppzksnark<default_r1cs_gg_ppzksnark_pp>(4, 1);
    return 0;
}
