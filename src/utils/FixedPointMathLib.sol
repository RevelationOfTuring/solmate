// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity >=0.8.0;

/// @notice Arithmetic library with operations for fixed-point numbers.
/// @author Solmate (https://github.com/transmissions11/solmate/blob/main/src/utils/FixedPointMathLib.sol)
/// @author Inspired by USM (https://github.com/usmfum/USM/blob/master/contracts/WadMath.sol)
/*
 * 功能总结：
 * 无符号 18 位小数定点数（wad）算术库，提供 WAD 乘除、通用 mulDiv、快速幂、整数平方根、unsafe 运算
 *
 * 核心函数：
 * - mulWadDown / mulWadUp：WAD 定点乘法（向下/向上取整）
 * - divWadDown / divWadUp：WAD 定点除法（向下/向上取整）
 * - mulDivDown / mulDivUp：通用 mulDiv（自定义分母）
 * - rpow：定点数快速幂（平方取幂法，O(log n)）
 * - sqrt：整数平方根（牛顿迭代法，7 次迭代）
 * - unsafeMod / unsafeDiv / unsafeDivUp：不检查除零的运算（省gas）
 *
 * 设计亮点：
 * 1. 纯 assembly 实现核心运算，避免 Solidity 溢出检查开销
 * 2. mulDiv 系列在 assembly 中手动检查溢出，比 unchecked 更精确
 * 3. rpow 使用平方取幂法（exponentiation by squaring），O(log n) 复杂度
 * 4. sqrt 使用牛顿迭代法（Babylonian method），固定 7 次迭代收敛
 *
 * 定点数基础：
 *   WAD 是 DeFi 中的标准定点数表示法（源自 MakerDAO 的 ds-math 库）：1 wad = 1e18
 *   两个 WAD 数相乘后要除以 WAD 才能保持精度（否则结果会多 18 位小数）
 */
library FixedPointMathLib {
    /*//////////////////////////////////////////////////////////////
                    SIMPLIFIED FIXED POINT OPERATIONS
    //////////////////////////////////////////////////////////////*/

    // uint256 最大值，供 assembly 中溢出检查使用
    // 注：assembly 不支持 type(uint256).max 语法，但 constant 会在编译时内联为字面量，assembly 可直接引用
    uint256 internal constant MAX_UINT256 = 2 ** 256 - 1;

    // WAD = 1e18，ETH 和大多数 ERC20 的精度标量
    uint256 internal constant WAD = 1e18;

    /*
     * @dev WAD 定点数乘法（向下取整）
     * x 和 y 都必须是 WAD 定点数（即实际值 × 1e18），结果也是 WAD 定点数
     * 计算 (x * y) / WAD，结果向下取整
     * 例：1.5 × 2.0 → mulWadDown(1.5e18, 2e18) = 3e18
     * @param x WAD 定点数（乘数）
     * @param y WAD 定点数（被乘数）
     * @return WAD 定点数乘积，向下取整
     */
    function mulWadDown(uint256 x, uint256 y) internal pure returns (uint256) {
        return mulDivDown(x, y, WAD);
    }

    /*
     * @dev WAD 定点数乘法（向上取整）
     * x 和 y 都必须是 WAD 定点数（即实际值 × 1e18），结果也是 WAD 定点数
     * 计算 (x * y) / WAD，结果向上取整
     * 用于需要"宁多勿少"的场景（如计算用户应还款金额）
     * @param x WAD 定点数（乘数）
     * @param y WAD 定点数（被乘数）
     * @return WAD 定点数乘积，向上取整
     */
    function mulWadUp(uint256 x, uint256 y) internal pure returns (uint256) {
        return mulDivUp(x, y, WAD);
    }

    /*
     * @dev WAD 定点数除法（向下取整）
     * x 和 y 都必须是 WAD 定点数（即实际值 × 1e18），结果也是 WAD 定点数
     * 计算 (x * WAD) / y，结果向下取整
     * 例：3.0 / 2.0 → divWadDown(3e18, 2e18) = 1.5e18
     * @param x WAD 定点数（被除数）
     * @param y WAD 定点数（除数，不能为 0）
     * @return WAD 定点数商，向下取整
     */
    function divWadDown(uint256 x, uint256 y) internal pure returns (uint256) {
        return mulDivDown(x, WAD, y);
    }

    /*
     * @dev WAD 定点数除法（向上取整）
     * x 和 y 都必须是 WAD 定点数（即实际值 × 1e18），结果也是 WAD 定点数
     * 计算 (x * WAD) / y，结果向上取整
     * @param x WAD 定点数（被除数）
     * @param y WAD 定点数（除数，不能为 0）
     * @return WAD 定点数商，向上取整
     */
    function divWadUp(uint256 x, uint256 y) internal pure returns (uint256) {
        return mulDivUp(x, WAD, y);
    }

    /*//////////////////////////////////////////////////////////////
                    LOW LEVEL FIXED POINT OPERATIONS
    //////////////////////////////////////////////////////////////*/

    /*
     * @dev 通用 mulDiv（向下取整）：计算 (x * y) / denominator，结果向下取整
     * 溢出检查：要求 denominator != 0 且 x * y 不溢出 uint256
     * @param x 乘数
     * @param y 被乘数
     * @param denominator 分母（不能为 0）
     * @return z 向下取整的商
     */
    function mulDivDown(uint256 x, uint256 y, uint256 denominator) internal pure returns (uint256 z) {
        /// @solidity memory-safe-assembly
        assembly {
            // Equivalent to require(denominator != 0 && (y == 0 || x <= type(uint256).max / y))

            // 溢出检查：确保两件事，即 denominator不为0 和 x * y 不溢出uint256
            // 等价于 denominator != 0 && (y == 0 || x <= MAX / y)
            //
            // 从内向外拆解：
            // 第 1 层：div(MAX_UINT256, y)
            // → MAX / y，即 y 能乘多大不溢出的上限
            // 第 2 层：gt(x, div(MAX_UINT256, y))
            // → x > MAX/y ? 1 : 0
            // → 如果为 1，说明 x * y 会溢出
            // 第 3 层：mul(y, gt(...))
            // → y * (溢出标志)
            // → 如果 y == 0：结果为 0，无论溢出标志是什么（因为 0 * 任何数 = 0）
            // → 如果 y != 0 且溢出：结果 > 0
            if iszero(mul(denominator, iszero(mul(y, gt(x, div(MAX_UINT256, y)))))) {
                revert(0, 0)
            }

            // 通过检查后，x * y 不会溢出，直接计算
            z := div(mul(x, y), denominator)
        }
    }

    /*
     * @dev 通用 mulDiv（向上取整）：计算 (x * y) / denominator，结果向上取整
     * 向上取整原理：ceil(a/b) = floor(a/b) + (a % b > 0 ? 1 : 0)
     *
     * 为什么不用传统的 (x * y + denominator - 1) / denominator？
     * 虽然 x * y 已通过溢出检查，但 x * y + denominator - 1仍可能溢出 uint256，
     * 需要额外的溢出检查。当前写法多算一次 mul(x, y)，但避免了额外的溢出风险
     *
     * @param x 乘数
     * @param y 被乘数
     * @param denominator 分母（不能为 0）
     * @return z 向上取整的商
     */
    function mulDivUp(uint256 x, uint256 y, uint256 denominator) internal pure returns (uint256 z) {
        /// @solidity memory-safe-assembly
        assembly {
            // 溢出检查（与mulDivDown 相同）
            if iszero(mul(denominator, iszero(mul(y, gt(x, div(MAX_UINT256, y)))))) {
                revert(0, 0)
            }

            // 向上取整 = 向下取整 + (余数 > 0 ? 1 : 0)
            z := add(gt(mod(mul(x, y), denominator), 0), div(mul(x, y), denominator))
        }
    }

    /*
     * @dev 定点数快速幂：计算 x的 n 次方，结果保持 scalar 定点精度
     *
     * 数学公式：result = x^n / scalar^(n-1)
     * 为什么要除以 scalar^(n-1)？
     *   x是定点数（实际值 × scalar），直接算 x^n 会得到 (实际值)^n × scalar^n
     *   但结果应该是 (实际值)^n × scalar（保持一个scalar 精度）
     *   所以要除掉多出的 scalar^(n-1)
     *
     * 算法：平方取幂法（exponentiation by squaring），O(log n) 复杂度
     * 核心思想：将 n 写成二进制，例如 n=13 = 1101₂
     *     x^13 = x^8 × x^4 × x^1
     *   只需要：
     *     - 不断平方得到 x^1, x^2, x^4, x^8 ...（每次迭代一次平方）
     *     - 遇到二进制位为 1 时，将当前的 x 幂次累乘到结果 z
     * 注：
     * 1. 定点数版本中每次乘法后要除以 scalar，并加 half 四舍五入：
     *     即整数除法 a / b 默认向下取整。如果要四舍五入，标准做法是 (a + b/2) / b）：
     *     x = (x² + half) / scalar
     *     z = (z × x + half) / scalar
     *
     * 2. 为什么要四舍五入而不是向下取整？
     *  答：rpow 循环中每次迭代都要除以 scalar，如果每次都向下取整，误差会随迭代次数累积，n 越大最终结果偏差越大。
     *     四舍五入让误差在正负之间抵消，减小累积误差。
     *
     * @param x 底数（scalar定点数）
     * @param n 指数（普通整数，不是定点数）
     * @param scalar 定点精度标量（如 WAD=1e18 或 RAY=1e27），不能为 0。如果scalar为0，会导致 div(xxRound, scalar) 在 EVM 中返回 0
     *        而不是 revert，使得结果静默错误。如果不需要定点精度（如纯整数快速幂 2^3），传 scalar = 1 即可。
     * @return z scalar 定点数格式的 x^n
     */
    function rpow(uint256 x, uint256 n, uint256 scalar) internal pure returns (uint256 z) {
        /// @solidity memory-safe-assembly
        assembly {
            switch x
            // 特殊处理 x == 0 的情况
            case 0 {
                // x == 0 时根据 n 的值决定结果
                switch n
                case 0 {
                    // 当x和n都==0时，结果应该为1.0（因为 0^0 定义为 1）
                    // 定点数中 1.0 = scalar
                    z := scalar
                }
                default {
                    // 当x==0，n!=0时，结果为0（因为0^n为0）
                    z := 0
                }
            }
            default {
                // 当x!=0时，先初始化 z
                // 平方取幂法从 n 的最高位开始不断右移，每次处理一位
                // 但循环从n >>= 1 开始，最低位（第0 位）不会被循环处理
                switch mod(n, 2)
                case 0 {
                    // 如果n是偶数，z = scalar（即 1.0，纯累乘器，等于没乘）
                    z := scalar
                }
                default {
                    // 如果n是奇数，z = x（把这个 x 先存到结果里）
                    z := x
                }

                // 计算half = scalar / 2，用于四舍五入
                // 每次定点除法 div(a + half, scalar) ≈ 四舍五入的 a / scalar
                let half := shr(1, scalar)

                // 循环条件：n != 0，即n还有二进制位需要处理
                for {
                    //循环初始化：n 右移 1 位，丢弃第 0 位（已在z的初始化中做了处理）
                    // 例：n = 13（1101₂）→ n = 6（110₂）
                    n := shr(1, n)
                } n {
                    // 迭代末尾：n 再右移 1 位，将下一个二进制位移到第 0 位
                    // 这样下次迭代中 mod(n, 2) 就能检查新的最低位
                    n := shr(1, n)
                } {
                    //---- 第一步：x = x² / scalar（底数自乘） ----
                    //
                    // 不管当前位是 0 还是 1，每次迭代都要平方
                    // 因为 x 代表的是"当前位的权重"，每升一位权重就要平方
                    // 溢出检查：如果 x 右移128位后结果不为0，说明 x >= 2^128。那么 x² >= 2^256，必定溢出 uint256
                    if shr(128, x) {
                        revert(0, 0)
                    }

                    // 计算x的平方（上面已经检查过x^2不溢出）
                    let xx := mul(x, x)

                    // 计算 xx + half（加scalar/2 实现四舍五入）
                    let xxRound := add(xx, half)

                    // 溢出检查：如果 xxRound < xx，说明 xx + half 产生溢出
                    if lt(xxRound, xx) {
                        revert(0, 0)
                    }

                    // 除以 scalar，得到定点数格式的 x²（四舍五入后的结果）
                    x := div(xxRound, scalar)

                    //---- 第二步：z = z × x / scalar（累乘到结果，仅当前位为 1 时） ----
                    if mod(n, 2) {
                        // 如果mod(n, 2)为1，表示当前n的最低位为 1，需要把 x 累乘到 z
                        // 计算 z * x
                        let zx := mul(z, x)

                        // 溢出检查：确保 (z × x) / x == z
                        if iszero(eq(div(zx, x), z)) {
                            // 但有个特殊情况：x == 0 时div(zx, x) 返回 0，不等于 z
                            // 这不是溢出，是除零，所以 x == 0 时不 revert
                            // 注：x可能在循环中被更新为 0（当 x² / scalar 向下取整为 0 时）
                            if iszero(iszero(x)) {
                                revert(0, 0)
                            }
                        }

                        // 计算 zx + half（加scalar/2 实现四舍五入）
                        let zxRound := add(zx, half)

                        // 溢出检查：如果 zxRound < zx，说明 zx + half 产生溢出
                        if lt(zxRound, zx) {
                            revert(0, 0)
                        }

                        // 除以 scalar，将 z × x 的四舍五入结果缩放回定点数精度
                        // 和前面 x = div(xxRound, scalar) 同理：两个定点数相乘后多了一个 scalar，需要除掉
                        z := div(zxRound, scalar)
                    }
                }
            }
        }
    }

    /*//////////////////////////////////////////////////////////////
                        GENERAL NUMBER UTILITIES
    //////////////////////////////////////////////////////////////*/

    /*
     * @dev 整数平方根（向下取整），返回 floor(sqrt(x))
     *
     * 算法：牛顿迭代法（又称巴比伦方法）
     *   求 sqrt(x) 就是找一个 z 使得 z² = x
     *   如果当前猜测值 z 偏大（z > sqrt(x)），那么 x/z 就偏小（x/z < sqrt(x)）
     *   真实答案夹在 z 和 x/z 之间，取平均值就更接近：
     *     z_new = (z + x / z) / 2
     *   反复执行，z 就会收敛到 sqrt(x)
     *
     *   例：x = 49，初始 z = 100
     *     第 1 次：(100 + 49/100) / 2 = 50.245
     *     第 2 次：(50.245 + 49/50.245) / 2 = 25.61
     *     ...反复几次收敛到 7
     *
     *   收敛速度：二次收敛——每次迭代正确位数翻倍
     *   但前提是初始估计不能太差，否则前几次只是线性收敛，浪费 gas
     *
     * 如何获取好的初始估计？思路链：拆分 → 近似 → 累积缩放因子 → 组合 → 迭代修正
     *   1. 拆分：x 的范围是 [0, 2^256)，跨度太大，无法直接用线性函数近似 sqrt
     *      所以先把 x 拆成 x = y × 2^k，利用 sqrt(y × 2^k) = sqrt(y) × sqrt(2^k) = sqrt(y) × 2^(k/2)
     *      只要把 y 压缩到一个小范围，就能用简单的线性函数近似 sqrt(y)
     *   2. 近似：y 被压缩到 [256, 256×2^16) 后，用线性函数近似 sqrt(y)：
     *      sqrt(y) ≈ 181 × (y + 65536) / 2^18
     *      这是在 [256, 256×2^16) 范围内经验选取的系数，最坏误差 ±2.84 倍
     *      不需要很精确，后面牛顿迭代会修正
     *   3. 累积缩放因子：2^(k/2) 不能等到最后再乘（多一次 mul），
     *      所以在拆分过程中每次 y >>= k 的同时，将 2^(k/2) 累积到 z（z <<= k/2）
     *      同时把常数 181 也提前塞进 z 的初始值，最后一步只需一次 mul
     *   4. 组合：拆分完成后 z = 181 × 2^(k/2)，一步算出初始估计：
     *      z = z × (y + 65536) >> 18 = sqrt(y) × 2^(k/2)≈ sqrt(x)
     *   5. 迭代修正：7 次牛顿迭代 z = (z + x/z) / 2，从±2.84 倍误差收敛到精确值
     *      最后做 floor 修正，确保返回 floor(sqrt(x))
     *
     * @param x 要求平方根的无符号整数
     * @return z floor(sqrt(x))
     */
    function sqrt(uint256 x) internal pure returns (uint256 z) {
        /// @solidity memory-safe-assembly
        assembly {
            // y是 x 的副本，用于位移缩放过程
            // x 本身保持不变，因为牛顿迭代公式 z = (z + x/z) / 2 需要原始值x
            let y := x

            // 数学推算：
            // 已知 sqrt(x) = sqrt(y) × 2^(k/2)
            // 其中 sqrt(y) 用线性近似：sqrt(y) ≈ 181 × (y + 65536) / 2^18
            // 代入得：sqrt(x) ≈ [181 × (y + 65536) / 2^18] × 2^(k/2) = 181 × 2^(k/2) × (y + 65536) / 2^18
            // 将z初始化成181，就是把 181 提前放进 z，让它在拆分过程中搭便车，最后少做一次乘法。
            z := 181

            // ---- 第一步：位移缩放，将 y 缩放到 [256, 256×2^16) 范围 ----
            //
            // 目的：线性近似只在 [256, 256×2^16) 范围内足够精确
            // 需要把任意大小的 y 缩放到这个范围
            //
            // 方法：类似二分搜索，4 次 if 分支确定 y 的大小级别
            //       每次检查 y >= 2^(k+8)，若是则 y >>= k，z <<= k/2
            //
            // 为什么 y 右移 k 位，z 要左移 k/2 位？
            //   y >>= k 相当于 y' = y / 2^k → 把 2^k 从 y 中拆出去，y 变小
            //   sqrt(y) = sqrt(y' × 2^k) = sqrt(y') × 2^(k/2)
            //   后面算出的是 sqrt(y')，需要乘回2^(k/2)
            //   z <<= k/2相当于提前把 z 左移 k/2 位，即预乘这个因子
            //
            // 为什么每次检查 y >= 2^(k+8) 而不是 y >= 2^k？
            //   为了保证 y >>= k 之后仍然 >= 256
            //   例如第 1 个分支：y >= 2^136 → y >>= 128 → y >= 2^8 = 256 ✅
            //   如果只检查 y >= 2^128，y = 2^128 右移后 y = 1，太小了
            //   y >= 256 是线性近似公式的前提，y太小时近似误差过大，7 次牛顿迭代可能不够收敛
            if iszero(lt(y, 0x10000000000000000000000000000000000)) {
                // 如果 y >= 2^136，即k为136-8=128
                //  y >>= 128, z <<= 64
                y := shr(128, y)
                z := shl(64, z)
            }
            if iszero(lt(y, 0x1000000000000000000)) {
                // 如果 y >= 2^72，即k为72-8=64
                //  y >>= 64, z <<= 32
                y := shr(64, y)
                z := shl(32, z)
            }
            if iszero(lt(y, 0x10000000000)) {
                // 如果 y >= 2^40，即k为40-8=32
                //  y >>= 32, z <<= 16
                y := shr(32, y)
                z := shl(16, z)
            }
            if iszero(lt(y, 0x1000000)) {
                // 如果 y >= 2^24，即k为24-8=16
                //  y >>= 16, z <<= 8
                y := shr(16, y)
                z := shl(8, z)
            }
            // 缩放完成后：y ∈ [256, 2^24)（当原始 x >= 256 时成立）
            //   解释：
            //     - 下界 256：每个分支检查 y >= 2^(k+8)，保证右移后 y >= 2^8 = 256
            //     - 上界 2^24：4 个分支协作，从高到低逐步压缩 y
            //         如果 y < 2^24，第 4 个分支不命中，y 不变，直接 < 2^24
            //         如果 y >= 2^24，第 4 个分支命中，右移 16 位
            //         而进入第 4 个分支时 y < 2^40（否则第 3 个分支会先命中并右移）
            //         所以右移 16 位后 y < 2^40 / 2^16 = 2^24
            //     - 按原始 x 分三种情况：
            //         - x < 256：4 个 if 都不命中，y 保持原值，不在此范围内，但牛顿迭代对小值也能收敛
            //         - 256 <= x < 2^24：4 个 if 都不命中，y 保持原值，恰好在 [256, 2^24) 内
            //         - x >= 2^24：至少命中第 4 个 if，缩放后 y 落入 [256, 2^24)
            //   z = 181 × 2^(k/2)，已累积常数 181 和 所有拆出的缩放因子

            // ---- 第二步：线性近似 ----
            //
            // 数学推导：
            //   设 a = y / 65536，因为y ∈ [256, 256×2^16)，则 a ∈ [1/256, 256)
            //   这样，就把 y 变换到一个关于 1对称的范围，线性近似在对称范围内误差分布更均匀
            //   之后作者在该范围内，用线性函数近似 sqrt：sqrt(a) ≈ (181/1024) × (a + 1)，并说明了误差范围为 ±2.84 倍
            //   （至于怎么选的——可能是数值优化，也可能是手动调参，注释中没有说明）
            //   于是，sqrt(y) = sqrt(65536 × a) = 256 × sqrt(a)
            //           ≈ 256 × (181/1024) × (a + 1)
            //           = (181/4) × (y/65536 + 1)
            //           = (181/4) × (y + 65536) / 65536
            //           = 181 × (y + 65536) / 262144
            //           = 181 × (y + 65536) / 2^18
            //
            // z = z × (y + 65536) >> 18，由于 z此时已经是 181 ×2^(k/2)（初始 181 + 位移缩放）
            // 所以 z × (y + 65536) >> 18 就是完整的初始估计
            z := shr(18, mul(z, add(y, 65536)))
            // 为什么不检查 z × (y + 65536) 是否溢出？因为一定不会溢出
            // 理由：计算前，y和z的值分别为
            // - y< 2^24（上界）
            // - z = 181 × 2^(k/2)，经过上面4个if分支总共最多右移 128 + 64 + 32 + 16 = 240 位，所以 k最大240，k/2 最大 120
            // 所以：y + 65536 < 2^24 + 65536 < 2^25
            //      z <= 181 × 2^120 < 2^128
            //      得到：  z × (y + 65536) < 2^128 × 2^25 = 2^153 < 2^256
            // 所以乘法一定不会溢出

            // ---- 第三步：牛顿迭代，共 7 次 ----
            //
            // 为什么需要这一步？
            // 第二步线性近似得到的 z 只是粗糙估计，误差在 ±2.84 倍以内
            //   例如 sqrt(x) = 100，z可能是 100/2.84=35 或 100*2.84=284，差太远不能直接用
            //   牛顿迭代从这个粗糙估计出发，逐步修正到精确值
            //
            // 公式：z = (z + x / z) / 2
            // 即shr(1, add(z, div(x, z)))
            //
            // 注意这里用的是原始的 x，不是缩放后的 y
            // 因为牛顿法求的是 sqrt(x)，y 只是用来算初始估计的
            //
            // 为什么是 7 次？
            //   初始估计误差在 ±2.84 倍的意思是：真实值和估计值的比值在 [1/2.84, 2.84] 之间
            //   位精度指的是二进制下有多少位是正确的。换算方法：log2(2.84) ≈ 1.5
            //   也就是说，估计值和真实值在二进制下，最多1.5 位是一致的，剩下的位都可能是错的
            //   由于牛顿迭代的每次迭代会让精度翻倍：1.5 → 3 → 6 → 12 → 24 → 48 → 96 → 192 位
            //   所以，7 次后达到 192 位精度，远超整数平方根所需的 128 位（uint256 的平方根最大为 2^128 - 1）
            z := shr(1, add(z, div(x, z)))
            z := shr(1, add(z, div(x, z)))
            z := shr(1, add(z, div(x, z)))
            z := shr(1, add(z, div(x, z)))
            z := shr(1, add(z, div(x, z)))
            z := shr(1, add(z, div(x, z)))
            z := shr(1, add(z, div(x, z)))

            // ---- 第四步：floor 修正 ----
            //
            // 牛顿迭代收敛后，z 一定是 floor(sqrt(x)) 或 ceil(sqrt(x)) 之一
            // 对于大多数 x，两者相等，不需要修正
            // 但有一种特殊情况：x夹在两个相邻平方数之间，且非常接近上面那个。例如 x = 8：
            //   - floor(sqrt(8)) = 2（因为 2² = 4 <= 8）
            //   - ceil(sqrt(8)) = 3（因为 3² = 9 > 8）
            // 牛顿迭代可能停在 z = 3 而不是 z = 2：
            //   - z = 3 时：z_new = (3 + 8/3) / 2 = (3 + 2) / 2 = 2
            //   - z = 2 时：z_new = (2 + 8/2) / 2 = (2 + 4) / 2 = 3
            // → z在 2 和 3 之间来回跳，最终停在哪个取决于迭代次数的奇偶
            //
            // 所以需要修正，判断 z 到底是 floor 还是 ceil：
            //   - 如果 x / z < z → z² > x  →  z > sqrt(x) → z 是 ceil，需要 -1
            //   - 如果 x / z >= z → z² <= x → z <= sqrt(x) → z 是 floor，不动
            // 以下代码就是上面所说的执行逻辑
            z := sub(z, lt(div(x, z), z))
            // 此时确保z是floor(sqrt(x))
        }
    }

    /** @dev 不安全的取模运算
     * 与Solidity 的 % 运算符不同，y == 0 时返回 0 而不是 revert
     * 省去了 Solidity 默认插入的除零检查，节省 gas
     * 适用于调用方已确保 y != 0 的场景
     * @param x 被除数
     * @param y 除数（调用方需确保 y != 0）
     * @return z x % y（y == 0 时返回 0）
     */
    function unsafeMod(uint256 x, uint256 y) internal pure returns (uint256 z) {
        /// @solidity memory-safe-assembly
        assembly {
            // 如果y为0，则返回0
            z := mod(x, y)
        }
    }

    /*
     * @dev 不安全的除法运算
     * 与 Solidity 的 / 运算符不同，y == 0 时返回 0 而不是 revert
     * 省去了 Solidity 默认插入的除零检查，节省 gas
     * 适用于调用方已确保 y != 0 的场景
     * @param x 被除数
     * @param y 除数（调用方需确保 y != 0）
     * @return r x / y 向下取整（y == 0 时返回 0）
     */
    function unsafeDiv(uint256 x, uint256 y) internal pure returns (uint256 r) {
        /// @solidity memory-safe-assembly
        assembly {
            // 如果y为0，则返回0
            r := div(x, y)
        }
    }

    /*
     * @dev 不安全的向上取整除法
     * 与 Solidity 的 / 运算符不同，y == 0 时返回 0 而不是 revert
     * 计算 ceil(x / y) = floor(x / y) + (x % y > 0 ? 1 : 0)
     * 适用于调用方已确保 y != 0 的场景
     * @param x 被除数
     * @param y 除数（调用方需确保 y != 0）
     * @return z ceil(x / y)（y == 0 时返回 0）
     */
    function unsafeDivUp(uint256 x, uint256 y) internal pure returns (uint256 z) {
        /// @solidity memory-safe-assembly
        assembly {
            // z等于floor(x / y) + (x % y > 0 ? 1 : 0)
            // 注：如果y为0，mod()和div()都返回0
            z := add(gt(mod(x, y), 0), div(x, y))
        }
    }
}
