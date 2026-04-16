// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0;

/// @notice Gas optimized merkle proof verification library.
/// @author Solmate (https://github.com/transmissions11/solmate/blob/main/src/utils/MerkleProofLib.sol)
/// @author Modified from Solady (https://github.com/Vectorized/solady/blob/main/src/utils/MerkleProofLib.sol)
/*
 * @title MerkleProofLib — Gas 优化的 Merkle 证明验证库
 * @notice 使用纯 assembly 实现 Merkle Proof 验证，零内存分配，仅使用 scratch space
 *
 * Merkle Tree 原理：
 * - 叶子节点是数据的哈希，两两配对向上哈希，最终得到唯一的 root
 * - 验证时只需 log2(N) 个兄弟节点（proof），从叶子逐层向上哈希，最终与 root 比较
 *
 *          root
 *         /    \
 *       H(AB)  H(CD)
 *       / \    / \
 *      A   B  C   D ← 叶子节点
 *
 * 验证 leaf=A 是否在树中：proof = [B, H(CD)]
 *  1. hash(A, B) → H(AB)
 *  2. hash(H(AB), H(CD)) → root
 *  3. 比较计算出的 root 与给定 root 是否相等
 */
library MerkleProofLib {
    /*
     * @dev 验证 Merkle 证明
     * @param proof 兄弟节点数组（从叶子到根方向的路径）
     * @param root 预期的 Merkle 树根哈希
     * @param leaf 待验证的叶子节点哈希
     * @return isValid 证明是否有效（计算出的根 == 给定的根）
     *
     * 关键优化：
     * 1. 使用 scratch space（内存地址 0x00~0x3f）存放两个哈希值，避免内存分配
     * 2. 每次迭代将较小值放 0x00、较大值放 0x20（排序后哈希，确保 hash(A,B) == hash(B,A)）
     * 3. xor(leafSlot, 32) 一条指令实现互补位置选择，避免 if/else 分支跳转，节省Gas
     * 4. 全程 assembly，无 Solidity 开销
     */
    function verify(bytes32[] calldata proof, bytes32 root, bytes32 leaf) internal pure returns (bool isValid) {
        /// @solidity memory-safe-assembly
        assembly {
            // 只有proof数组非空时才需要逐层计算
            if proof.length {
                // proof.length * 32 = 总字节数，shl(5, x) 等价于 x * 32
                // proof.offset：数组proof第一个元素（proof[0]）在 calldata 中的字节起始位置
                // end = proof 在 calldata 中的结束偏移量
                let end := add(proof.offset, shl(5, proof.length))

                // offset 初始指向 proof[0] 在 calldata 中的位置
                let offset := proof.offset

                // 逐个proof 元素迭代，从叶子向上计算哈希
                // 注：使用 for {} 1 {} 而非 for {} lt(offset, end) {}
                //  等价于 do-while 循环：外层 if proof.length 已保证至少一个元素，
                //  第一次迭代无条件执行，末尾 if iszero(lt(offset, end)) { break } 控制退出
                //  相当于 do { ... } while (offset < end)，省去首次进入循环的 lt 判断
                // prettier-ignore
                for {} 1 {} {    
                    // 决定 leaf 放在 scratch space 的哪个位置：
                    // - 若 leaf > proof[i]：leafSlot = 32（leaf 放地址 0x20，proof[i] 放地址 0x00）
                    // - 若 leaf <= proof[i]：leafSlot = 0（leaf 放地址 0x00，proof[i] 放地址 0x20）
                    // 效果：较小值始终在前32 字节，较大值在后 32 字节 → 排序后哈希
                    let leafSlot := shl(5, gt(leaf, calldataload(offset)))

                    // 将 leaf 写入 scratch space 的 leafSlot 位置（0x00 或 0x20）
                    mstore(leafSlot, leaf)
                    // 将 proof[i] 写入 leafSlot 的互补位置：
                    // xor(0, 32) = 32，xor(32, 32) = 0 → leaf 放哪，proof[i] 就放另一个
                    // 用 xor 一条指令实现二选一，避免 if/else 分支跳转，省gas
                    mstore(xor(leafSlot, 32), calldataload(offset))

                    // 对 scratch space 0x00~0x3f 共64 字节的内容做 keccak256 哈希
                    // 结果覆写 leaf，作为下一层迭代的输入
                    leaf := keccak256(0, 64)
                    
                    // offset移动到下一个 proof 元素（+32 字节）
                    offset := add(offset, 32)

                    // 如果移动后的offset>=end，说明所有 proof 元素处理完毕则退出循环
                    // prettier-ignore
                    if iszero(lt(offset, end)) { break }
                }
            }

            // proof为空时：直接比较 leaf == root（单节点树或空树）
            // proof非空时：比较逐层哈希后的最终值 == root
            isValid := eq(leaf, root)
        }
    }
}
