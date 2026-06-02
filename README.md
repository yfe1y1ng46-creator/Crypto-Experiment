# Crypto Experiment

现代密码学实验代码仓库。

## Experiment 1

目录：`experiment1/`

包含 Cryptopals Set 1 与 MysteryTwister C3 SHA1 题目的 Python 实现。

### 文件说明

- `solve_experiment1.py`：实验一完整求解脚本，覆盖编码转换、固定 XOR、单字节 XOR、重复密钥 XOR 破解和 MTC3 SHA1 口令恢复。
- `challenge6_only.py`：第六题 Break repeating-key XOR 的单独实现，输出 keysize、key 和明文。
- `mtc3_sha1_only.py`：MTC3 Cracking SHA1-Hashed Passwords 的单独实现，输出命中密码、SHA1 和运行时间。
- `cryptopals_4.txt`：Cryptopals Challenge 4 数据文件。
- `cryptopals_6.txt`：Cryptopals Challenge 6 数据文件。

### 运行方式

```powershell
cd experiment1
python solve_experiment1.py
python challenge6_only.py
python mtc3_sha1_only.py
```

### 关键结果

- Challenge 6 keysize：`29`
- Challenge 6 key：`Terminator X: Bring the noise`
- Challenge 6 re-encrypt check：`True`
- MTC3 password：`(Q=win*5`
- MTC3 SHA1：`67ae1a64661ac8b4494666f58c4822408dd0a3e4`

说明：第 3、4、6 题恢复的明文包含歌词内容，报告中使用长度、哈希和重新加密校验描述结果。

## Experiment 2

目录：`experiment2/`

包含 MTC3 ePassport MRZ AES key 题，以及 Cryptopals Set 2 的 AES ECB/CBC、PKCS#7、oracle、cut-and-paste 和 bit flipping 相关实现。

```powershell
cd experiment2
python -m pip install -r requirements.txt
python mtc3_epassport_aes.py
python challenge09_pkcs7_padding.py
python challenge10_cbc_mode.py
python challenge11_ecb_cbc_detection_oracle.py
python challenge12_byte_at_a_time_ecb_simple.py
python challenge13_ecb_cut_and_paste.py
python challenge14_byte_at_a_time_ecb_harder.py
python challenge15_pkcs7_validation.py
python challenge16_cbc_bitflipping.py
```

关键结果：

- MTC3 completed MRZ：`12345678<8<<<1110182<1111167<<<<<<<<<<<<<<<4`
- MTC3 AES key：`ea8645d97ff725a898942aa280c43179`
- MTC3 codeword：`Kryptographie`
- ECB cut-and-paste：`role=admin`
- CBC bitflipping admin：`true`

## Experiment 3

目录：`experiment3/`

包含 Project Euler 182 的 RSA unconcealed messages 求解，以及 Cryptopals Challenge 39 的 RSA 实现。

```powershell
cd experiment3
python experiment3_solution.py
```

关键结果：

- Euler 182 minimum unconcealed messages：`9`
- Euler 182 number of best e：`217800`
- Euler 182 sum of e：`399788195976`
- RSA roundtrip ok：`True`
