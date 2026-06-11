use ark_bn254::Fr;
use ark_ff::PrimeField;

use crate::mimc::{bn254::MimcBn254, MiMC};

const CHUNK_BITS: usize = 250;

fn bytes_to_bits_be(data: &[u8]) -> Vec<bool> {
    data.iter()
        .flat_map(|byte| (0..8).rev().map(move |i| (byte >> i) & 1 == 1))
        .collect()
}

fn le_bits_to_fp<F: PrimeField>(bits: &[bool]) -> F {
    let mut result = F::zero();
    let mut power = F::one();
    for bit in bits {
        if *bit {
            result += power;
        }
        power.double_in_place();
    }
    result
}

pub fn compress_bytes(data: &[u8], chunk_bits: usize) -> Vec<Fr> {
    let bits = bytes_to_bits_be(data);
    bits.chunks(chunk_bits)
        .map(|chunk| {
            let mut padded = vec![false; chunk_bits];
            for (i, bit) in chunk.iter().enumerate() {
                padded[i] = *bit;
            }
            le_bits_to_fp(&padded)
        })
        .collect()
}

pub fn mimc_commit(data: &[u8]) -> Fr {
    let state = compress_bytes(data, CHUNK_BITS);
    MimcBn254::permute_feistel(&state, 1)[0]
}

pub fn cipher_commitment(cipher: &[u8]) -> Fr {
    mimc_commit(cipher)
}

pub fn prompt_commitment(prompt: &[u8]) -> Fr {
    mimc_commit(prompt)
}

#[cfg(test)]
mod test {
    use ark_bn254::Fr;
    use ark_ff::PrimeField;
    use ark_r1cs_std::{
        alloc::AllocVar,
        fields::{fp::FpVar, FieldVar},
        prelude::{Boolean, ToBitsGadget},
        uint8::UInt8,
        R1CSVar,
    };
    use ark_relations::{ns, r1cs::ConstraintSystem};

    use crate::{
        commitment::{cipher_commitment, compress_bytes, CHUNK_BITS},
        mimc::{
            bn254::{constraint::MimcBn254Var, MimcBn254},
            MiMC,
        },
        utils::compress_var,
    };

    #[test]
    fn native_compress_matches_circuit() {
        let data = (0..128).map(|i| i as u8).collect::<Vec<_>>();
        let cs = ConstraintSystem::<Fr>::new_ref();
        let bits = data
            .iter()
            .flat_map(|byte| {
                UInt8::<Fr>::constant(*byte)
                    .to_bits_be()
                    .unwrap()
                    .into_iter()
                    .map(|b| b.value().unwrap())
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let bit_vars: Vec<Boolean<Fr>> = bits.iter().map(|b| Boolean::constant(*b)).collect();
        let circuit = compress_var(&bit_vars, CHUNK_BITS).unwrap();
        let native = compress_bytes(&data, CHUNK_BITS);
        assert_eq!(circuit.len(), native.len(), "compress length mismatch");
        for (lhs, rhs) in circuit.iter().zip(native.iter()) {
            assert_eq!(lhs.value().unwrap(), *rhs);
        }
        let _ = cs;
    }

    #[test]
    fn native_cipher_commitment_matches_circuit() {
        let data = (0..128).map(|i| i as u8).collect::<Vec<_>>();
        let native = cipher_commitment(&data);

        let cs = ConstraintSystem::<Fr>::new_ref();
        let cipher_vars = data
            .iter()
            .map(|b| UInt8::<Fr>::constant(*b))
            .collect::<Vec<_>>();
        let mut cipher_bits = vec![];
        for c in cipher_vars {
            cipher_bits.extend(c.to_bits_be().unwrap());
        }
        let compress_cipher = compress_var(&cipher_bits, CHUNK_BITS).unwrap();
        let round_constant_vars = MimcBn254::ROUND_KEYS
            .iter()
            .map(|c| FpVar::new_constant(ns!(cs, "round key"), *c).unwrap())
            .collect::<Vec<_>>();
        let mimc_var = MimcBn254Var::new(1, &round_constant_vars, FpVar::zero());
        let circuit = mimc_var.generate_constraints(&compress_cipher)[0]
            .value()
            .unwrap();

        assert_eq!(native, circuit);
    }
}
