# hk_bmc_upgrade_tool_by_python2
Tool for upgrading BMC firmware in batches By Python2.7
iBMC批量升降级工具使用说明
前置条件：安装有Python2.7运行环境
0.进入该工具主目录
1.安装所需依赖:pip install -r requirements.txt
2.编辑config目录下的文件env.csv.按照对应格式传入BMC_IP,BMC_USER,BMC_PASSWORD,OS_IP,OS_USER,OS_PASSWORD.（OS_IP,OS_USER,OS_PASSWORD 没有则不用传入）
3.按照firmware目录下的文件夹放入对应的BMC,BIOS,CPLD固件
4.执行python main.py -h 查看帮助如下：
    usage: main.py [-h] [-m {upgrade,downgrade}] [-e {VD,VE}]
                [-t {BMC,BIOS,CPLD,ALL}] [-f FILEPATH]

    Tool for upgrading BMC firmware in batches By Python2.7
    optional arguments:
    -h, --help            show this help message and exit
    -m {upgrade,downgrade}, --mode {upgrade,downgrade}
                            Upgrade Mode:upgrade, downgrade, default=upgrade
    -e {VD,VE}, --env {VD,VE}
                            BMC Env Type:VD, VE, default=VD
    -t {BMC,BIOS,CPLD,ALL}, --type {BMC,BIOS,CPLD,ALL}
                            Firmware Type:BMC, BIOS, CPLD, ALL, default=BMC
    -f FILEPATH, --filepath FILEPATH
                            User Defined Upgrade FilePath, default=None
    -p {TRUE,FALSE}, --parallel  {TRUE,FALSE}
                        Parallel Upgrade:TRUE, FALSE, default=TRUE
5.参数说明：
    -m {upgrade,downgrade} 升级模式：升级或降级，默认升级
    -e {VD,VE} 升级环境类型：VD或VE，默认VD
    -t {BMC,BIOS,CPLD,ALL} 升级固件类型：BMC、BIOS、CPLD、ALL(BMC/CPLD/BIOS),默认升级BMC
    -f FILEPATH 手动传入任意指定的升级固件绝对路径，此时 -m -e 参数失效，默认为空
    -p {TRUE,FALSE} 并行升级:TRUE、FALSE，默认为TRUE,并行升级;传入FALSE则串行升级

6.使用示例：
    批量升级BMC、CPLD、BIOS: python main.py -t ALL
    批量并行降级VE环境的BIOS: python main.py -m downgrade -e VE -t BIOS
	批量串行升级VD环境的BMC: python main.py -m upgrade -e VD -t BMC -p FALSE (可简写为:python main.py -p FALSE)
	

7.日志说明：
    工具运行日志：已当前IP+日期+指定的文件名为文件保存，升级BMC后会自动一键收集BMC日志。OS_IP,OS_USER,OS_PASSWORD则升级BIOS后会收集OS指定日志install 
    工具搜集BMC/OS日志：script_logs，已当前日期为文件保存
