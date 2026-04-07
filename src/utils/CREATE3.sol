// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity >=0.8.0;

import {Bytes32AddressLib} from "./Bytes32AddressLib.sol";

/// @notice Deploy to deterministic addresses without an initcode factor.
/// @author Solmate (https://github.com/transmissions11/solmate/blob/main/src/utils/CREATE3.sol)
/// @author Modified from 0xSequence (https://github.com/0xSequence/create3/blob/master/contracts/Create3.sol)
/*
 * 功能总结：
 * CREATE3 部署库—— 实现与 initcode 无关的确定性地址部署。
 *
 * 核心问题：
 * - CREATE2 的地址 = f(deployer, salt, keccak256(initcode))
 *   → 如果合约构造函数参数变了，initcode 变了，部署地址也变了
 * - CREATE3 的地址 = f(deployer, salt) —— 与 initcode 完全无关
 *
 * 实现原理（两步部署）：
 *   1. 用 CREATE2 部署一个固定字节码的"代理合约"（PROXY）
 *      → 代理地址 = f(deployer, salt, keccak256(PROXY_BYTECODE))
 *      → 因为 PROXY_BYTECODE 是常量，所以代理地址只取决于 deployer + salt
 *   2. 代理合约收到 calldata（真正的 creationCode）后，用 CREATE 部署最终合约
 *      → 最终地址 = f(proxy_address, nonce=1)
 *      → 因为 proxy 地址确定+ nonce 固定为 1，所以最终地址也确定
 *
 * 结果：最终合约地址只取决于 deployer + salt，与 creationCode 无关
 *
 * 调用链：
 *   deploy(salt, creationCode, value)
 *     → CREATE2 部署 proxy（固定字节码）
 *       → proxy.call(creationCode)
 *         → proxy 内部用 CREATE 部署最终合约
 *           → 最终合约地址 = RLP(proxy_address, 1)
 */
library CREATE3 {
    // 启用 bytes32 的方法链调用（.fromLast20Bytes()）
    using Bytes32AddressLib for bytes32;

    /*
     * 代理合约的完整字节码（16 字节），包含 initcode 和 runtime 两部分。
     * 字节码布局：[initcode 部分将runtime 嵌入为PUSH8 的立即数]
     *
     *   hex"67 363d3d37363d34f0 3d 52 6008 6018 f3"
     *        ↑  ↑ ↑ ↑ ↑ ↑ ↑ ↑ ↑
     *        │  └─ runtime（8字节，被PUSH8 嵌入，即0x363d3d37363d34f0）
     *        └─ initcode 外壳（8字节），即0x67...3d5260086018f3
     *
     * 执行顺序：
     *   CREATE2 部署时→ 执行 initcode → 返回 runtime 作为 deployed code
     *   后续调用 proxy → 执行 runtime → 将 calldata 通过 CREATE 部署为新合约
     *
     * Gas 优化技巧 —— 为什么用 0x3d（RETURNDATASIZE）而不是 0x6000（PUSH1 0）来压入 0？
     *   - RETURNDATASIZE 返回上一次外部调用的返回数据长度
     *   - 在 proxy 执行上下文中，无论是 initcode 还是 runtime 阶段，
     *     在使用 0x3d 的位置之前都没有发生过外部调用，所以 RETURNDATASIZE 一定为 0
     *   - 对比：
     *     PUSH1 0x00     = 0x60 0x00 → 2 字节，3 gas
     *     RETURNDATASIZE = 0x3d      → 1 字节，2 gas
     *   - 本字节码中共使用 3 次 0x3d，总计节省 3 字节 + 3 gas
     *   - 对于 CREATE2 部署的合约，字节码越短越好（每字节 200 gas 部署成本）
     *   - 这是 EVM 汇编中常见的优化 pattern（EIP-1167 最小代理合约中也使用了同样技巧）
     *
     *   补充：EIP-3855（Shanghai 升级，2023.04）引入了 PUSH0（0x5f）操作码
     *   - PUSH0：1 字节，2 gas，无条件压入 0，语义更清晰
     *   - 与 RETURNDATASIZE 性能完全一致（同为 1 字节 + 2 gas），
     *     但无需依赖"之前没有外部调用"的前提条件
     *   - Solmate 编写时 PUSH0 尚未引入，因此使用 RETURNDATASIZE 作为当时的最佳实践
     *   - 保留 RETURNDATASIZE 也确保了对所有 EVM 版本的向后兼容性
     *     （PUSH0仅在 Shanghai 及之后的链上可用，旧链会报invalid opcode）
     * ═══════════════════════════════════════════════════════════
     * 一、initcode（CREATE2 部署 proxy 时执行）
     * 功能：将 runtime 字节码返回，使其成为 proxy 的 deployed code
     * ═══════════════════════════════════════════════════════════
     *
     * ---------------------------------------------------------------------
     *  Opcode     | Opcode + Arguments    | Description      | Stack View
     * ---------------------------------------------------------------------
     *  0x67       |  0x67XXXXXXXXXXXXXXXX | PUSH8 bytecode   | bytecode
     *    → 将 8 字节的 runtime 字节码（0x363d3d37363d34f0）压入栈
     *  0x3d       |  0x3d                 | RETURNDATASIZE   | 0 bytecode
     *  0x52       |  0x52                 | MSTORE           |
     *    → MSTORE(offset=0, value=bytecode)
     *    → 将 runtime 字节码写入内存（右对齐在 32 字节slot的低 8 字节）
     *    → 内存: [零 24字节][runtime 8字节]
     *  0x60       |  0x6008               | PUSH1 08         | 8
     *  0x60       |  0x6018               | PUSH1 18         | 24 8
     *  0xf3       |  0xf3                 | RETURN           |
     *    → RETURN(offset=24, size=8)
     *    → 返回内存偏移 24 开始的 8 字节 = runtime 字节码
     *    → 这 8 字节成为 proxy 合约的 deployed code
     * ---------------------------------------------------------------------
     *
     * ═══════════════════════════════════════════════════════════
     * 二、runtime（proxy 被调用时执行）
     * 功能：将 calldata 原样传给 CREATE，部署为新合约
     * ═══════════════════════════════════════════════════════════
     *
     * ----------------------------------------------------------------------
     *  Opcode     | Opcode + Arguments    | Description      | Stack View
     * ----------------------------------------------------------------------
     *  0x36       |  0x36                 | CALLDATASIZE     | size
     *  0x3d       |  0x3d                 | RETURNDATASIZE   | 0 size
     *  0x3d       |  0x3d                 | RETURNDATASIZE   | 0 0 size
     *  0x37       |  0x37                 | CALLDATACOPY     |
     *    → CALLDATACOPY(destOffset=0, offset=0, size=calldatasize)
     *    → 将完整 calldata 拷贝到内存 0x00 开始的位置
     * ----------------------------------------------------------------------
     *  0x36       |  0x36                 | CALLDATASIZE     | size
     *  0x3d       |  0x3d                 | RETURNDATASIZE   | 0 size
     *  0x34       |  0x34                 | CALLVALUE        | value 0 size
     *  0xf0       |  0xf0                 | CREATE           | newContract
     *    → CREATE(value=callvalue, offset=0, size=calldatasize)
     *    → 用 calldata（= creationCode）+ 转入的 ETH 部署新合约
     * ----------------------------------------------------------------------
     */
    bytes internal constant PROXY_BYTECODE = hex"67_36_3d_3d_37_36_3d_34_f0_3d_52_60_08_60_18_f3";

    /*
     * @dev 代理合约字节码的hash，用于 CREATE2 地址预计算
     * 因为 PROXY_BYTECODE 是常量，所以 PROXY_BYTECODE_HASH 也是常量
     * 在 getDeployed() 中作为 CREATE2 地址公式的bytecodeHash 参数
     */
    bytes32 internal constant PROXY_BYTECODE_HASH = keccak256(PROXY_BYTECODE);

    /*
     * @dev 通过 CREATE3 模式部署合约，实现与 initcode 无关的确定性地址
     * @param salt         用户自定义的盐值，与 deployer 地址共同决定最终合约地址
     * @param creationCode 目标合约的完整创建字节码（包含构造函数参数）
     * @param value        部署时转给目标合约的 ETH 数量（wei）
     * @return deployed    最终部署的合约地址
     *
     * 执行流程：
     *   1. 将常量字节码拷贝到 memory（assembly 的 create2 只能从 memory 读取）
     *   2. 用 CREATE2 + salt 部署 proxy 合约 → proxy 地址确定
     *   3. 预计算最终合约地址（基于 proxy 地址 + nonce=1）
     *   4. 调用 proxy.call(creationCode)，proxy 内部用 CREATE 部署最终合约
     *   5. 校验部署成功（proxy 和最终合约都不能为空）
     */
    function deploy(bytes32 salt, bytes memory creationCode, uint256 value) internal returns (address deployed) {
        // 这里拷贝到 memory 是因为 assembly 的 create2 只能从 memory 读取数据
        bytes memory proxyChildBytecode = PROXY_BYTECODE;

        address proxy;
        /// @solidity memory-safe-assembly
        assembly {
            // 用 CREATE2 部署 proxy 合约
            // add(proxyChildBytecode, 32)：跳过 bytes 的前 32 字节长度前缀，指向实际字节码
            // mload(proxyChildBytecode)：读取字节码长度（= 16 字节）
            // create2(value, offset, size, salt) → 部署并返回新合约地址
            // value=0：不给 proxy 转 ETH（ETH 是给最终合约的）
            proxy := create2(0, add(proxyChildBytecode, 32), mload(proxyChildBytecode), salt)
        }
        // proxy 地址为 0 说明 CREATE2 失败（如 salt 已被使用过）
        require(proxy != address(0), "DEPLOYMENT_FAILED");

        // 预计算最终合约地址（不依赖实际部署，纯数学推导）
        deployed = getDeployed(salt);
        // 调用 proxy 合约，传入 creationCode 作为 calldata + 附带 ETH
        // proxy 的 runtime 逻辑会执行 CREATE(value, 0, calldatasize)
        // → 用 creationCode 部署最终合约，并将 value 转给它
        (bool success, ) = proxy.call{value: value}(creationCode);
        // 双重校验：
        // 1. success = true → proxy 调用没有 revert
        // 注：大多情况call proxy都会返回true，只有在该call的过程中gas不足会返回false
        // 2. deployed.code.length != 0 → 最终地址确实有合约代码
        //    （proxy不检查 CREATE 返回值，即使 constructor revert 导致 CREATE 失败，
        //     proxy.call 仍会返回 success=true，所以必须额外检查目标地址是否有代码）
        require(success && deployed.code.length != 0, "INITIALIZATION_FAILED");
    }

    /*
     * @dev 预计算 CREATE3 部署的最终合约地址（以当前合约为deployer）
     * @param salt 用户自定义的盐值
     * @return     最终合约地址
     *
     * 便捷重载：自动将 address(this) 作为 creator 参数
     */
    function getDeployed(bytes32 salt) internal view returns (address) {
        return getDeployed(salt, address(this));
    }

    /*
     * @dev 预计算 CREATE3 部署的最终合约地址（指定任意 deployer）
     * @param salt    用户自定义的盐值
     * @param creator 部署者地址（即调用 deploy() 的合约地址）
     * @return        最终合约地址
     *
     * 推导过程（两步）：
     *
     * 第一步：计算 proxy 地址（CREATE2 公式）
     *   proxy = keccak256(0xFF ++ creator ++ salt ++ keccak256(PROXY_BYTECODE))[12:32]
     *   - 0xFF：CREATE2 地址前缀（EIP-1014）
     *   - creator：部署者地址
     *   - salt：用户自定义盐值
     *   - PROXY_BYTECODE_HASH：proxy 字节码的哈希（常量）
     *   - [12:32]：取 keccak256 结果的低 20 字节作为地址
     *
     * 第二步：计算最终合约地址（CREATE 公式 = RLP 编码）
     *   deployed = keccak256(RLP([proxy, 1]))[12:32]
     *   - RLP 编码结构：0xd6 0x94 <proxy 20字节> 0x01
     *     - 0xd6 = 0xc0 + 0x16（0xc0 是 RLP list 短前缀，0x16=22 是后续内容长度）
     *     - 0x94 = 0x80 + 0x14（0x80 是 RLP string 短前缀，0x14=20 是 address 长度）
     *     - proxy：代理合约地址（20 字节）
     *     - 0x01：proxy 的 nonce（第一次 CREATE 时 nonce=1）
     *   - [12:32]：取低 20 字节作为地址
     */
    function getDeployed(bytes32 salt, address creator) internal pure returns (address) {
        // 第一步：用 CREATE2 公式计算 proxy 地址
        address proxy = keccak256(
            abi.encodePacked(
                // CREATE2 前缀
                bytes1(0xFF),
                // 部署者地址
                creator,
                // 用户盐值
                salt,
                // proxy 字节码哈希（常量）
                PROXY_BYTECODE_HASH
            )
        ).fromLast20Bytes(); // 取 keccak256 结果的低 20 字节得到 proxy 地址

        // 第二步：用 CREATE（RLP 编码）公式计算最终合约地址
        return
            keccak256(
                abi.encodePacked(
                    // RLP 编码 [proxy, 1] 的完整字节序列：
                    // 1. 0xd6为RLP list 前缀。
                    // RLP 规则：当 list 总长度 ≤ 55 字节时，前缀 = 0xc0 + 字节长度
                    // 即0xd6 = 0xc0（list 前缀）+ 0x16（字节长度 22= 1 + 20 + 1）
                    // 2. 0x94为RLP string 前缀。
                    // RLP 规则：当 string 长度 ≥ 2 且≤ 55 字节时，前缀 = 0x80 + string长度
                    // 即0x94 = 0x80（string 前缀）+ 0x14（address长度20）
                    // 完整的RLP结构图：
                    // d6          ← list 前缀：后续共 22 字节
                    // ├── 94      ← string 前缀：后续 20 字节是 address
                    // │   └── <proxy address>  ← 20 字节
                    // └── 01      ← nonce = 1（单字节直接编码）
                    hex"d6_94",
                    // 代理合约地址（20 字节）
                    proxy,
                    // nonce = 1（proxy 第一次执行 CREATE）
                    hex"01"
                )
            ).fromLast20Bytes(); // 取低 20 字节 → 最终合约地址
    }
}
