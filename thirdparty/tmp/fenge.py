def split_file(input_file, lines_per_file=1000):
    # 打开输入文件
    with open(input_file, 'r', encoding='utf-8') as file:
        lines = file.readlines()

    # 计算分割文件的数量
    total_lines = len(lines)
    num_files = (total_lines // lines_per_file) + (1 if total_lines % lines_per_file != 0 else 0)

    # 将文件分割成多个小文件
    for i in range(num_files):
        # 获取当前文件的起始行和结束行
        start = i * lines_per_file
        end = start + lines_per_file
        output_filename = f"{input_file}_part_{i + 1}.txt"

        # 写入分割文件
        with open(output_filename, 'w', encoding='utf-8') as output_file:
            output_file.writelines(lines[start:end])
        print(f"已创建分割文件：{output_filename}")


# 调用函数，输入原始文件路径和每个文件的行数
split_file('your_file.txt', 1000)
