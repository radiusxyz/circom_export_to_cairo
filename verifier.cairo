#This is a template for cairo based on verifier_groth16.sol.ejs on snarkjs/templates
# %lang starknet
%builtins output pedersen range_check

from starkware.cairo.common.cairo_builtins import HashBuiltin
from starkware.cairo.common.bool import FALSE, TRUE
from starkware.cairo.common.math import assert_nn, unsigned_div_rem
from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.serialize import serialize_word

from alt_bn128_g1 import G1Point, ec_add, ec_mul
from alt_bn128_g2 import G2Point
from alt_bn128_pair import pairing
from alt_bn128_field import FQ12, is_zero, FQ2, fq12_diff, fq12_eq_zero, fq12_mul, fq12_one
from bigint import BigInt3

struct VerifyingKey:
    member alfa1 : G1Point      
    member beta2 : G2Point      
    member gamma2 : G2Point 
    member delta2 : G2Point 
    member IC : G1Point*
    member IC_length : felt

end

struct Proof:
	member A : G1Point 
	member B : G2Point 
	member C : G1Point 

end

#Auxiliary functions (Builders)
#Creates a G1Point from the received felts: G1Point(x,y)
func BuildG1Point{range_check_ptr : felt}(x1 : felt, x2 : felt, x3 : felt, y1 : felt, y2 : felt, y3 : felt) -> (r: G1Point):
    alloc_locals
    let X : BigInt3 = BigInt3(x1,x2,x3)
    let Y : BigInt3 = BigInt3(y1,y2,y3)

    return (G1Point(X,Y))

end
        
#Creates a G2Point from the received felts: G2Point([a,b],[c,d])
func BuildG2Point{range_check_ptr : felt}(a1 : felt, a2 : felt, a3 : felt, b1 : felt, b2 : felt, b3 : felt, c1 : felt, c2 : felt, c3 : felt, d1 : felt, d2 : felt, d3 : felt) -> (r : G2Point):
    alloc_locals
    let A : BigInt3 = BigInt3(a1,a2,a3)
    let B : BigInt3 = BigInt3(b1,b2,b3)
    let C : BigInt3 = BigInt3(c1,c2,c3)    
    let D : BigInt3 = BigInt3(d1,d2,d3)

    let x : FQ2 = FQ2(B,A)
    let y : FQ2 = FQ2(D,C)

    return (G2Point(x, y))

end

#Returns negated BigInt3
func negateBigInt3{range_check_ptr : felt}(n : BigInt3) -> (r : BigInt3):
    let (_, nd0) = unsigned_div_rem(n.d0, 60193888514187762220203335)
    let d0 = 60193888514187762220203335 -nd0
    let (_, nd1) = unsigned_div_rem(n.d1, 104997207448309323063248289)
    let d1 = 104997207448309323063248289 -nd1
    let (_, nd2) = unsigned_div_rem(n.d2, 3656382694611191768777987)
    let d2 = 3656382694611191768777987 -nd2

    return(BigInt3(d0,d1,d2))

end

#Returns negated G1Point(addition of a G1Point and a negated G1Point should be zero)
func negate{range_check_ptr : felt}(p : G1Point) -> (r: G1Point):
    alloc_locals
    let x_is_zero : felt = is_zero(p.x)
	if x_is_zero == TRUE:
        let y_is_zero : felt = is_zero(p.y)
		if y_is_zero == TRUE:
            return (G1Point(BigInt3(0,0,0),BigInt3(0,0,0)))
        end
    end

    let neg_y : BigInt3 = negateBigInt3(p.y)
    return (G1Point(p.x, neg_y))
end

#Computes the pairing for each pair of points in p1 and p2, multiplies each new result and returns the final result
#pairing_result should iniially be an fq12_one
func compute_pairings{range_check_ptr : felt}(p1 : G1Point*, p2 : G2Point*, pairing_result : FQ12, position : felt, length : felt) -> (result : FQ12):
        if position != length:
            let current_pairing_result : FQ12 = pairing(p2[position], p1[position])
            let mul_result : FQ12 = fq12_mul(pairing_result, current_pairing_result) 

            return compute_pairings(p1, p2,mul_result, position+1, length)
        end
        return(pairing_result)
    end

#Returns the result of computing the pairing check
func pairings{range_check_ptr : felt}(p1 : G1Point*, p2: G2Point*, length : felt) -> (r : felt):
    alloc_locals
    assert_nn(length)
    let initial_result : FQ12 = fq12_one()
    let pairing_result : FQ12 = compute_pairings(p1,p2,initial_result,0,length)

    let one : FQ12 = fq12_one()
    let diff : FQ12 = fq12_diff(pairing_result, one)
    let result : felt = fq12_eq_zero(diff)
    return(result)
 end

#Pairing check for four pairs
func pairingProd4{range_check_ptr : felt}(a1 : G1Point, a2 : G2Point, b1 : G1Point, b2 : G2Point, c1 : G1Point, c2 : G2Point, d1 : G1Point, d2 : G2Point) -> (r : felt):
    let (p1 : G1Point*) = alloc()
    let (p2 : G2Point*) = alloc()

    assert p1[0] = a1
    assert p1[1] = b1
    assert p1[2] = c1
    assert p1[3] = d1

    assert p2[0] = a2
    assert p2[1] = b2
    assert p2[2] = c2
    assert p2[3] = d2

    return pairings(p1,p2,4)

end

func verifyingKey{range_check_ptr : felt}() -> (vk : VerifyingKey):
    alloc_locals
	let alfa1 : G1Point = BuildG1Point(
        20147928508986928787614913872544572682799306601237887700177494224837695902438, 6435765495205822310103159663057480283022159978919381149133098307060997619016, 1,
       0, 0, 0,
    )

    let beta2 : G2Point = BuildG2Point(
        0, 0, 0,
        10128820203616779926387540244748324378613042659969438184153629038597162751152, 5121075047373715329664775895884484145160611218868405682931619152027897809757, 0,
        0, 0, 0,
        17282859026320142220263983448595555294062983862077927664357360170901796638939, 18386037389383234987051116642514481515933896649746137673165603476566815694843, 0
    )

    let gamma2 : G2Point = BuildG2Point(
        0, 0, 0,
        10857046999023057135944570762232829481370756359578518086990519993285655852781, 11559732032986387107991004021392285783925812861821192530917403151452391805634, 0,
        0, 0, 0,
        8495653923123431417604973247489272438418190587263600148770280649306958101930, 4082367875863433681332203403145435568316851327593401208105741076214120093531, 0
    )
    let delta2 : G2Point = BuildG2Point(
        0, 0, 0,
        5936496241528871333487005839361481374445149620373860137322638618296557597562, 20323250991520858691381033018249915156865519717446285796279856136622899028799, 0,
        0, 0, 0,
        16677401923891818143401041482386364379309956362619023464153881831908643916877, 8715559163861194628109530730334191347455598187034824430696214173982187010047, 0
    )
        
    let (IC : G1Point*) = alloc()
    
    let point_0 : G1Point =  BuildG1Point( 
        1441567157966568932032068437984091084777046302976863392107274361322382077271, 14169078713292030880152682933069971659318839012630498057238459949279071813318, 1,
        0, 0, 0)
    assert IC[0] =  point_0                                   
    
    let point_1 : G1Point =  BuildG1Point( 
        4091406810365289346953977482157161678324697565439895797493479056404219510133, 6154364762279038002348039727140139373519879194449802731269711250302372357184, 1,
        0, 0, 0)
    assert IC[1] =  point_1                                   
    
    let IC_length : felt = 2 

    return(VerifyingKey(alfa1, beta2, gamma2, delta2, IC, IC_length))

end
    
#Computes the linear combination for vk_x
func vk_x_linear_combination{range_check_ptr : felt}( vk_x : G1Point, input : BigInt3*, position : felt, length : felt, IC : G1Point*) -> (result_vk_x : G1Point):
    if position != length:
        let mul_result : G1Point = ec_mul(IC[position + 1], input[position])
        let add_result : G1Point = ec_add(vk_x, mul_result)
    
        return vk_x_linear_combination(add_result, input, position + 1, length,  IC)
    end
        return(vk_x)
end

func verify{range_check_ptr : felt}(input : BigInt3*, proof: Proof, input_len : felt) -> (r : felt):
    alloc_locals
    let vk : VerifyingKey = verifyingKey()
    assert input_len = vk.IC_length + 1
    let initial_vk_x : G1Point = BuildG1Point(0, 0, 0, 0, 0, 0)
    let computed_vk_x : G1Point = vk_x_linear_combination(initial_vk_x, input, 0, vk.IC_length - 1, vk.IC)
    let vk_x : G1Point = ec_add(computed_vk_x, vk.IC[0])

    let neg_proof_A : G1Point = negate(proof.A)
    return pairingProd4(neg_proof_A, proof.B , vk.alfa1, vk.beta2, vk_x, vk.gamma2, proof.C, vk.delta2)

end

#Fills the empty array output with the BigInt3 version of each number in input
func getBigInt3array{range_check_ptr : felt}(input : felt*, output : BigInt3*, input_position, output_position, length):
    if output_position != length:
        let big_int : BigInt3 = BigInt3(input[input_position], input[input_position + 1], input[input_position +2])
        assert output[output_position] = big_int

        getBigInt3array(input,output,input_position+3, output_position+1,length)
        return()
    end
    return()
end

#a_len, b1_len, b2_len and c_len are all 6, input_len would be 3 * amount of inputs
# @external
func verifyProof{pedersen_ptr : HashBuiltin*, range_check_ptr : felt}(a_len : felt, a : felt*, b1_len : felt, b1 : felt*, b2_len : felt, b2 : felt*,
                                         c_len : felt, c : felt*, input_len : felt, input : felt*) -> (r : felt):
    alloc_locals
    let A : G1Point = BuildG1Point(a[0], a[1], a[2], a[3], a[4], a[5])
    let B : G2Point = BuildG2Point(b1[0], b1[1], b1[2], b1[3], b1[4], b1[5], b2[0], b2[1], b2[2], b2[3], b2[4], b2[5])
    let C : G1Point = BuildG1Point(c[0], c[1], c[2], c[3], c[4], c[5])

    let (big_input : BigInt3*) = alloc()
    getBigInt3array(input, big_input, 0, 0, input_len/3)

    let proof : Proof = Proof(A, B, C)
    let result : felt = verify(big_input, proof, input_len)
    return(result)

end

func main{output_ptr: felt*, pedersen_ptr : HashBuiltin*, range_check_ptr: felt}():

    let (a_ptr) = alloc()
    assert[a_ptr] = 0x16435458185497151578792433
    assert[a_ptr + 1] = 0x40172872974813924995536275
    assert[a_ptr + 2] = 0x3258538799375934883692565
    assert[a_ptr + 3] = 0x18053195823741242528076033
    assert[a_ptr + 4] = 0x63793431666194470068739038
    assert[a_ptr + 5] = 0x2763392202904072211382205

    let (b1_ptr) = alloc()
    assert[b1_ptr] = 39203446000482540257637925
    assert[b1_ptr + 1] = 8372331185708158742649818
    assert[b1_ptr + 2] = 1940944301260288891776770
    assert[b1_ptr + 3] = 14539866263615908413985012
    assert[b1_ptr + 4] = 28351972057156804035626776
    assert[b1_ptr + 5] = 3102459511026671344229042

    let (b2_ptr) = alloc()
    assert[b2_ptr] = 9828654912686566717924955417256841697967210538615635764100151140618360804409
    assert[b2_ptr + 1] = 6772645713857459030422926379766787335917025233797487247375005857295124934612
    assert[b2_ptr + 2] = 0
    assert[b2_ptr + 3] = 0
    assert[b2_ptr + 4] = 0
    assert[b2_ptr + 5] = 0

    let (c_ptr) = alloc()
    assert[c_ptr] = 9669763424470073022223052725001037709110572894164303206529499188575040771700
    assert[c_ptr + 1] = 16542524330523657154492704737691731273902297249897120965339882439355551551745
    assert[c_ptr + 2] = 1
    assert[c_ptr + 3] = 0
    assert[c_ptr + 4] = 0
    assert[c_ptr + 5] = 0

    let (input_ptr) = alloc()
    assert [input_ptr] = 33
    assert [input_ptr + 1] = 0
    assert [input_ptr + 2] = 0

    let result : felt = verifyProof(6, a_ptr, 6, b1_ptr, 6, b2_ptr, 6, c_ptr, 3, input_ptr)
    serialize_word(result)
    return ()
end