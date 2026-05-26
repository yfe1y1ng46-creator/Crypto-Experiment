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
