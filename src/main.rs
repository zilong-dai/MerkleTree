use dusk_bls12_381::BlsScalar;
use hex;

// const HASH_LEN: usize = 32;

fn bytes_2_blascalar(inputs: Vec<u8>) -> Vec<BlsScalar> {
    inputs
        .chunks(32)
        .map(|scalar_bytes| {
            BlsScalar::from_bytes(&match scalar_bytes.len() % 32 {
                0 => scalar_bytes[0..32].try_into().unwrap(),
                _ => {
                    let mut arr = [0u8; 32];
                    arr[0..scalar_bytes.len()].copy_from_slice(scalar_bytes);
                    arr
                }
            })
            .unwrap()
        })
        .collect::<Vec<BlsScalar>>()
}

pub fn to_hex_int(ch: u8) -> u8 {
    let res = match ch {
        48..=57 => ch - 48,
        97..=102 => ch - 87,
        65..=70 => ch - 55,
        _ => unreachable!(),
    };
    res % 16
}

fn poseidon_hash(inputs: &[BlsScalar]) -> BlsScalar {
    dusk_poseidon::sponge::hash(&inputs)
}

#[derive(Clone, Debug)]
struct Leave {
    // index: usize,
    value: Vec<u8>,
    isEmpty: bool,
}

impl ToString for Leave {
    fn to_string(&self) -> String {
        self.value
            .iter()
            .map(|d| format!("{:02X}", d))
            .collect::<Vec<String>>()
            .join("")
    }
}

#[derive(Clone, Debug)]
struct Inner {
    hash: BlsScalar,
}

#[derive(Debug, Clone)]
struct MerkleTree {
    root: Inner,
    leaves: Vec<Leave>,
    inners: Vec<Inner>,
    depth: usize,
}

#[derive(Debug)]
struct MerkleProof {
    index: usize,
    value: String,
    siblings: Vec<BlsScalar>,
    root: BlsScalar,
    empty: bool,
}

impl MerkleTree {
    fn new(depth: usize) -> MerkleTree {
        MerkleTree {
            root: Inner {
                hash: BlsScalar::zero(),
            },
            leaves: vec![
                Leave {
                    value: vec![],
                    isEmpty: true
                };
                2usize.pow((depth - 1) as u32)
            ],
            inners: vec![],
            depth: depth,
        }
    }

    fn leave_num(&self) -> usize {
        2usize.pow(self.depth as u32)
    }

    fn insert_leaf(&mut self, position: usize, data: Vec<u8>) {
        if position >= self.leave_num() {
            panic!("position out of bound");
        }

        match self.leaves.last() {
            Some(leaf) => {
                if leaf.isEmpty == false {
                    println!("insert error");
                } else {
                    self.leaves.insert(
                        position,
                        Leave {
                            value: data.clone(),
                            isEmpty: false,
                        },
                    );
                    self.leaves.pop();
                    self.build();
                }
            }
            _ => println!("last leave error"),
        }

        self.build();
    }


    fn build(&mut self) {
        let mut nodes: Vec<BlsScalar> = self
            .leaves
            .clone()
            .iter()
            .map(|node| poseidon_hash(&bytes_2_blascalar(node.value.clone())))
            .collect();
        self.inners = nodes
            .iter()
            .map(|&scalar| Inner {
                hash: scalar.clone(),
            })
            .collect();

        // 可以只更新变化的inner节点, todo!()

        while nodes.len() > 1 {
            let mut new_nodes = Vec::new();

            for chunk in nodes.chunks(2) {
                let hash = poseidon_hash(&chunk);
                new_nodes.push(hash.clone());

                self.inners.push(Inner { hash: hash });
            }

            if nodes.len() % 2 != 0 {
                let hash = nodes.pop().unwrap();
                new_nodes.push(hash);
            }

            nodes = new_nodes;
            // self.depth += 1;
        }

        self.root = Inner {
            hash: nodes.pop().unwrap(),
        };
    }

    fn generate_proof(&self, leaf_index: usize) -> MerkleProof {
        let mut proof = Vec::new();
        let mut index = leaf_index;

        let mut nodes = self.inners.clone();

        for i in 0..self.depth - 1 {
            let sibling_index = if index % 2 == 0 { index + 1 } else { index - 1 };

            proof.push(nodes[sibling_index + self.calc_pos(i)].clone().hash);
            index = index / 2;
        }

        MerkleProof {
            index: leaf_index,
            value: self.leaves[leaf_index].to_string(),
            siblings: proof,
            root: self.root.clone().hash,
            empty: self.leaves[leaf_index].isEmpty,
        }
    }

    fn calc_pos(&self, dep: usize) -> usize {
        2usize.pow(self.depth as u32) - 2usize.pow((self.depth - dep) as u32)
    }

    fn verify_proof(&self, proof: MerkleProof) -> bool {
        let mut index = proof.index;
        let mut current_hash = match proof.empty {
            true => BlsScalar::zero(),
            false => {
                let inputs = hex::decode(proof.value).unwrap();
                poseidon_hash(&bytes_2_blascalar(inputs))
            }
        };

        for sibling in proof.siblings.iter() {
            if index % 2 == 0 {
                current_hash = poseidon_hash(&[current_hash, *sibling]);
            } else {
                current_hash = poseidon_hash(&[*sibling, current_hash]);
            }
            index = index / 2;
        }
        current_hash == proof.root
    }
}

fn main() {

    let mut merkle_tree = MerkleTree::new(8);

    merkle_tree.insert_leaf(1, b"leaf1".to_vec());
    merkle_tree.insert_leaf(1, b"leaf2".to_vec());
    merkle_tree.insert_leaf(1, b"leaf3".to_vec());
    merkle_tree.insert_leaf(1, b"leaf4".to_vec());


    let proof = merkle_tree.generate_proof(1);

    println!("{}", merkle_tree.verify_proof(proof));
}

#[test]
fn test_hash_2_string() {
    // let hash = BlsScalar { data: [0u8; 32] };
    // println!("{} {}", hash.to_string(), hash.to_string().len());

    let leaf = Leave {
        value: vec![0u8; 32],
        isEmpty: false,
    };
    println!("{} {}", leaf.to_string(), leaf.to_string().len());
}

