# 演示项目：TaskNote

TaskNote 是一个极简的命令行待办事项工具，用于 TraceShield 沙箱链路演示。

## 功能

- `tasknote add <内容>`：添加一条待办事项
- `tasknote list`：列出全部待办事项
- `tasknote done <编号>`：标记完成

## 设计要点

1. 数据保存在用户目录下的 `.tasknote.json`，单文件、无外部依赖。
2. 命令行解析使用标准库 argparse，输出统一走 stdout。
3. 项目自身不含网络功能，适合在离线沙箱中演示。

## 目录结构

```
tasknote/
├── README.md
├── tasknote.py    # 主程序
└── tests/
    └── test_tasknote.py
```

## 免责声明

本文件仅为演示用途，描述的功能未实现。
