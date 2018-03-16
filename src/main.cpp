#include <libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp>

//hash
#include <libsnark/gadgetlib1/gadgets/hashes/sha256/sha256_gadget.hpp>

//key gen 
#include "libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp" //hold key

// ZoKrates
#include <ZoKrates/wraplibsnark.cpp>


using namespace libsnark;
using namespace libff;

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

template<typename FieldT>
void constraint_to_json(linear_combination<FieldT> constraints, std::stringstream &ss)
{
    ss << "{";
    uint count = 0;
    for (const linear_term<FieldT>& lt : constraints.terms)
    {
        if (count != 0) {
            ss << ",";
        }
        if (lt.coeff != 0 && lt.coeff != 1) {
            ss << '"' << lt.index << '"' << ":" << "-1";
        }
        else {
            ss << '"' << lt.index << '"' << ":" << lt.coeff;
        }
        count++;
    }
    ss << "}";
}

template <typename FieldT>
void array_to_json(protoboard<FieldT> pb, uint input_variables,  std::string path)
{

    std::stringstream ss;
    std::ofstream fh;
    fh.open(path, std::ios::binary);

    r1cs_variable_assignment<FieldT> values = pb.full_variable_assignment();
    ss << "\n{\"TestVariables\":[";

    for (size_t i = 0; i < values.size(); ++i)
    {

        ss << values[i].as_bigint();
        if (i <  values.size() - 1) { ss << ",";}
    }

    ss << "]}\n";
    ss.rdbuf()->pubseekpos(0, std::ios_base::out);

    fh << ss.rdbuf();
    fh.flush();
    fh.close();
}

template<typename FieldT>
void r1cs_to_json(protoboard<FieldT> pb, uint input_variables, std::string path)
    {
    // output inputs, right now need to compile with debug flag so that the `variable_annotations`
    // exists. Having trouble setting that up so will leave for now.
    r1cs_constraint_system<FieldT> constraints = pb.get_constraint_system();
    std::stringstream ss;
    std::ofstream fh;
    fh.open(path, std::ios::binary);

    ss << "\n{\"variables\":[";
    
    for (size_t i = 0; i < input_variables + 1; ++i) 
    {   
        ss << '"' << constraints.variable_annotations[i].c_str() << '"';
        if (i < input_variables ) {
            ss << ", ";
        }
    }
    ss << "],\n";
    ss << "\"constraints\":[";
     
    for (size_t c = 0; c < constraints.num_constraints(); ++c)
    {
        ss << "[";// << "\"A\"=";
        constraint_to_json(constraints.constraints[c].a, ss);
        ss << ",";// << "\"B\"=";
        constraint_to_json(constraints.constraints[c].b, ss);
        ss << ",";// << "\"A\"=";;
        constraint_to_json(constraints.constraints[c].c, ss);
        if (c == constraints.num_constraints()-1 ) {
            ss << "]\n";
        } else {
            ss << "],\n";
        }
    }
    ss << "]}";
    ss.rdbuf()->pubseekpos(0, std::ios_base::out);
    fh << ss.rdbuf();
    fh.flush();
    fh.close();
}

template<typename FieldT>
void exportInput(r1cs_primary_input<FieldT> input){
    cout << "\tInput in Solidity compliant format:{" << endl;
    for (size_t i = 0; i < input.size(); ++i)
    {
              cout << "\t\tinput[" << i << "] = " << HexStringFromLibsnarkBigint(input[i].as_bigint()) << ";" << endl;
    }
    cout << "\t\t}" << endl;
}

bool replace(std::string& str, const std::string& from, const std::string& to) {
    size_t start_pos = str.find(from);
    if(start_pos == std::string::npos)
        return false;
    str.replace(start_pos, from.length(), to);
    return true;
}

void proof_to_json(r1cs_ppzksnark_proof<libff::alt_bn128_pp> proof) {
    std::cout << "proof.A = Pairing.G1Point(" << outputPointG1AffineAsHex(proof.g_A.g)<< ");" << endl;
    std::cout << "proof.A_p = Pairing.G1Point(" << outputPointG1AffineAsHex(proof.g_A.h)<< ");" << endl;
    std::cout << "proof.B = Pairing.G2Point(" << outputPointG2AffineAsHex(proof.g_B.g)<< ");" << endl;
    std::cout << "proof.B_p = Pairing.G1Point(" << outputPointG1AffineAsHex(proof.g_B.h)<<");" << endl;
    std::cout << "proof.C = Pairing.G1Point(" << outputPointG1AffineAsHex(proof.g_C.g)<< ");" << endl;
    std::cout << "proof.C_p = Pairing.G1Point(" << outputPointG1AffineAsHex(proof.g_C.h)<<");" << endl;
    std::cout << "proof.H = Pairing.G1Point(" << outputPointG1AffineAsHex(proof.g_H)<<");"<< endl;
    std::cout << "proof.K = Pairing.G1Point(" << outputPointG1AffineAsHex(proof.g_K)<<");"<< endl; 


    std::string path = "proof.json";
    std::stringstream ss;
    std::ofstream fh;
    fh.open(path, std::ios::binary);
    
    ss << "{\n";
    ss << " \"a\" :[" << outputPointG1AffineAsHex(proof.g_A.g) << "],\n";
    ss << " \"a_p\"  :[" << outputPointG1AffineAsHex(proof.g_A.h)<< "],\n";
    ss << " \"b\"  :[" << outputPointG2AffineAsHex(proof.g_B.g)<< "],\n";
    ss << " \"b_p\" :[" << outputPointG1AffineAsHex(proof.g_B.h)<< "],\n";
    ss << " \"c\" :[" << outputPointG1AffineAsHex(proof.g_C.g)<< "],\n";
    ss << " \"c_p\" :[" << outputPointG1AffineAsHex(proof.g_C.h)<< "],\n";
    ss << " \"h\" :[" << outputPointG1AffineAsHex(proof.g_H)<< "],\n";
    ss << " \"k\" :[" << outputPointG1AffineAsHex(proof.g_K)<< "],\n";
    ss << " \"input\" :" << "[]"; //TODO: add inputs 
    ss << "}";
    ss.rdbuf()->pubseekpos(0, std::ios_base::out);
    fh << ss.rdbuf();
    fh.flush();
    fh.close();

}

void buildVerificationContract(r1cs_ppzksnark_keypair<libff::alt_bn128_pp> keypair, std::string path ) {

    std::stringstream ss;
    std::ofstream fh;
    fh.open(path, std::ios::binary);
    unsigned icLength = keypair.vk.encoded_IC_query.rest.indices.size() + 1;
    
    ss << "{\n";
    ss << " \"a\" :[" << outputPointG2AffineAsHex(keypair.vk.alphaA_g2) << "],\n";
    ss << " \"b\"  :[" << outputPointG1AffineAsHex(keypair.vk.alphaB_g1) << "],\n";
    ss << " \"c\" :[" << outputPointG2AffineAsHex(keypair.vk.alphaC_g2) << "],\n";
    ss << " \"g\" :[" << outputPointG2AffineAsHex(keypair.vk.gamma_g2)<< "],\n";
    ss << " \"gb1\" :[" << outputPointG1AffineAsHex(keypair.vk.gamma_beta_g1)<< "],\n";
    ss << " \"gb2\" :[" << outputPointG2AffineAsHex(keypair.vk.gamma_beta_g2)<< "],\n";
    ss << " \"z\" :[" << outputPointG2AffineAsHex(keypair.vk.rC_Z_g2)<< "],\n";

    ss <<  "\"IC\" :[" << outputPointG1AffineAsHex(keypair.vk.encoded_IC_query.first);
    
    for (size_t i = 1; i < icLength; ++i)
    {   
        auto vkICi = outputPointG1AffineAsHex(keypair.vk.encoded_IC_query.rest.values[i - 1]);
        ss << "," <<  vkICi;
    } 
    ss << "]";


    ss << "}";
    ss.rdbuf()->pubseekpos(0, std::ios_base::out);
    fh << ss.rdbuf();
    fh.flush();
    fh.close();


}

template<typename FieldT>
//void dump_key(r1cs_constraint_system<FieldT> cs)
void dump_key(protoboard<FieldT> pb, std::string path)
{

    r1cs_constraint_system<FieldT> constraints = pb.get_constraint_system();
    std::stringstream ss;
    std::ofstream fh;
    fh.open(path, std::ios::binary);


    r1cs_ppzksnark_keypair<libff::alt_bn128_pp> keypair = generateKeypair(pb.get_constraint_system());
    serializeProvingKeyToFile(keypair.pk, "pk_path");
    serializeVerificationKeyToFile(keypair.vk, "vk_path");

    pb.primary_input();
    pb.auxiliary_input();

    r1cs_primary_input <FieldT> primary_input = pb.primary_input();
    r1cs_auxiliary_input <FieldT> auxiliary_input = pb.auxiliary_input();
    ss << "primaryinputs" << primary_input;
    ss << "aux input" << auxiliary_input;

    r1cs_ppzksnark_proof<libff::alt_bn128_pp> proof = r1cs_ppzksnark_prover<libff::alt_bn128_pp>(keypair.pk, primary_input, auxiliary_input);

    buildVerificationContract(keypair, "vk.json");
    proof_to_json (proof);

    ss.rdbuf()->pubseekpos(0, std::ios_base::out);
    fh << ss.rdbuf();
    fh.flush();
    fh.close();

}


template<typename FieldT>
void test_r1cs_ppzksnark(size_t num_constraints)
{
    const size_t new_num_constraints = num_constraints - 1;
    protoboard<libff::Fr<FieldT>> pb;
    // create variable A
    pb_variable_array<libff::Fr<FieldT> > A;
    // Create variable B
    pb_variable_array<libff::Fr<FieldT> > B;
    // Create variable res
    pb_variable<libff::Fr<FieldT> > res;

    res.allocate(pb, "res");
    A.allocate(pb, new_num_constraints, "A");
    B.allocate(pb, new_num_constraints, "B");
    pb.set_input_sizes(1);
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
    compute_inner_product.generate_r1cs_witness();
    assert(pb.is_satisfied());
    std::cout << "num vars: " << pb.num_variables() << "\n";   // output r1cs as json
    r1cs_to_json(pb, 7, "r1cs.json");
    array_to_json(pb, 7, "tests.json");
    // output input variable for testing
    // dump_key(pb, "key.json");
    r1cs_primary_input <libff::Fr<FieldT>> primary_input = pb.primary_input();
    r1cs_auxiliary_input <libff::Fr<FieldT>> auxiliary_input = pb.auxiliary_input();


    exportInput(primary_input);
    exportInput(auxiliary_input);

    
}

int main () {

    libff::alt_bn128_pp::init_public_params();
    test_r1cs_ppzksnark<alt_bn128_pp>(4);

    return 0;
}
