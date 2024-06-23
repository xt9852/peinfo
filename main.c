/**
 *\file     main.c
 *\author   xt
 *\version  0.0.1
 *\brief             主模块实现, UTF-8(No BOM)
 *          时间|事件
 *          -|-
 *          2022.02.06|创建文件
 *          2024.06.23|添加Doxygen注释
 */
#include <stdio.h>
#include <stdlib.h>
#include <tchar.h>
#include <Windows.h>
#include <CommCtrl.h>

#define SIZEOF(x)               sizeof(x)/sizeof(x[0])                      ///< 计算数量

#define SP(...)                 _stprintf_s(txt, SIZEOF(txt), __VA_ARGS__)  ///< 格式化输出

TCHAR *g_title                  = _T("peinfo");                             ///< 文件标题

HFONT  g_font                   = NULL;                                     ///< 字体句柄

HWND   g_tree                   = NULL;                                     ///< 窗体句柄

TCHAR  g_section_name[16][16]   = {0};                                      ///< 节信息

typedef struct _DATA                                                        ///  数据顶
{
    UCHAR size;                                                             ///< 数据项长
    TCHAR *name;                                                            ///< 数据项名称

} DATA, *PDATA;


/**
 *\brief                        转成UNCOIDE字符
 *\param[in]    dst             目标
 *\param[in]    src             源
 *\return                       无
 */
void to_unicode(TCHAR *dst, char *src)
{
    int dst_len = lstrlen(dst);
    int src_len = strlen(src);

    for (int i = 0; i < (src_len + 1); i++) // 转成UNCOIDE字符,多加1个结尾
    {
        dst[dst_len + i] = src[i];
    }
}

/**
 *\brief                        通过地址查找节
 *\param[in]    nt              头节点
 *\param[in]    addr            地址
 *\return                       数量
 */
int search_section(PIMAGE_NT_HEADERS nt, DWORD addr)
{
    PIMAGE_OPTIONAL_HEADER32 opt     = (PIMAGE_OPTIONAL_HEADER32)&(nt->OptionalHeader);
    PIMAGE_SECTION_HEADER    section = (PIMAGE_SECTION_HEADER)(nt + 1);

    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++)
    {
        DWORD size = (section->Misc.VirtualSize + opt->SectionAlignment - 1) /
                      opt->SectionAlignment *
                      opt->SectionAlignment; // 取整

        if (addr >= section->VirtualAddress && addr <= (section->VirtualAddress + size - 1))
        {
            return i;
        }

        section++;
    }

    return -1;
}

/**
 *\brief                        在树中插入DOS节点数据项
 *\param[in]    tree            树句柄
 *\param[in]    parent          父节点句柄
 *\param[in]    buff            PE文件数据
 *\return                       无
 */
void insert_dos_head(HWND tree, HTREEITEM parent, UCHAR *buff)
{
    DATA data_item[] = {
        { 2,  _T("可执行文件标记                 ")},
        { 2,  _T("文件最后页的字节数             ")},
        { 2,  _T("文件页数                       ")},
        { 2,  _T("重定位元素个数                 ")},
        { 2,  _T("以段落为单位的头部大小         ")},
        { 2,  _T("所需的最小附加段               ")},
        { 2,  _T("所需的最大附加段               ")},
        { 2,  _T("初始的堆栈段(SS)相对偏移量值   ")},
        { 2,  _T("初始的堆栈指针(SP)值           ")},
        { 2,  _T("校验和                         ")},
        { 2,  _T("初始的指令指针(IP)值           ")},
        { 2,  _T("初始的代码段(CS)相对偏移量值   ")},
        { 2,  _T("重定位表在文件中的偏移地址     ")},
        { 2,  _T("覆盖号                         ")},
        { 8,  _T("保留字,一般都是为确保对齐而预留")},
        { 2,  _T("OEM标识符,相对于e_oeminfo      ")},
        { 2,  _T("OEM信息,即e_oemid的细节        ")},
        { 20, _T("保留字,一般都是为确保对齐而预留")},
        { 4,  _T("指向PE文件头的偏移量           ")}
    };

    TCHAR txt[128]    = _T("");

    TVINSERTSTRUCT tv = {0};
    tv.hParent        = parent;
    tv.hInsertAfter   = TVI_LAST;
    tv.item.mask      = TVIF_TEXT;
    tv.item.pszText   = txt;

    int    fa         = 0; // DOS头节点在exe文件中的位置
    TCHAR *name       = 0;
    UCHAR  size       = 0;

    // 插入DOS头数据项
    for (int i = 0; i < SIZEOF(data_item); i++)
    {
        name = data_item[i].name;
        size = data_item[i].size;

        if (2 == size)  // 2字节数据项
        {
            SP(_T("%04x %s : %04x"), fa, name, *(WORD*)(buff + fa));
        }
        else if (4 == size)
        {
            SP(_T("%04x %s : %08x"), fa, name, *(DWORD*)(buff + fa));
        }
        else if (8 == size)
        {
            SP(_T("%04x %s : %08x%08x"), fa, name, *(DWORD*)(buff + fa), *(DWORD*)(buff + fa + 4));
        }
        else
        {
            SP(_T("%04x %s : %08x%08x%08x%08x%08x"), fa, name,
                *(DWORD*)(buff + fa),
                *(DWORD*)(buff + fa + 4),
                *(DWORD*)(buff + fa + 8),
                *(DWORD*)(buff + fa + 12),
                *(DWORD*)(buff + fa + 16));
        }

        TreeView_InsertItem(tree, &tv);

        fa += size;
    }
}

/**
 *\brief                        在树中插入FILE节点数据项
 *\param[in]    tree            树句柄
 *\param[in]    parent          父节点句柄
 *\param[in]    buff            PE文件数据
 *\return                       无
 */
void insert_file_head(HWND tree, HTREEITEM parent, UCHAR *buff)
{
    TCHAR txt[128];

    DATA data_item[] = {
        { 2, _T("可执行文件的目标CPU类型        ")},
        { 2, _T("PE文件的节区的个数             ")},
        { 4, _T("文件创建时间                   ")},
        { 4, _T("符号表                         ")},
        { 4, _T("符号数量                       ")},
        { 2, _T("IMAGE_OPTIONAL_HEADER结构的大小")},
        { 2, _T("指定文件的类型                 ")}
    };

    PIMAGE_DOS_HEADER  dos  = (PIMAGE_DOS_HEADER)buff;
    PIMAGE_NT_HEADERS  nt   = (PIMAGE_NT_HEADERS)(buff + dos->e_lfanew);
    PIMAGE_FILE_HEADER file = (PIMAGE_FILE_HEADER)&(nt->FileHeader);

    TVINSERTSTRUCT tv       = {0};
    tv.hParent              = parent;
    tv.hInsertAfter         = TVI_LAST;
    tv.item.mask            = TVIF_TEXT;
    tv.item.pszText         = txt;

    int    fa               = (UCHAR*)file - buff; // FILE头节点在exe文件中的位置
    TCHAR *name             = 0;
    UCHAR  size             = 0;

    for (int i = 0; i < SIZEOF(data_item); i++)
    {
        name = data_item[i].name;
        size = data_item[i].size;

        if (2 == size)  // 2字节数据项
        {
            SP(_T("%04x %s : %04x"), fa, name, *(WORD*)(buff + fa));
        }
        else
        {
            SP(_T("%04x %s : %08x"), fa, name, *(DWORD*)(buff + fa));
        }

        TreeView_InsertItem(tree, &tv);

        fa += size;
    }
}

/**
 *\brief                        在树中插入OPTION节点数据项
 *\param[in]    tree            树句柄
 *\param[in]    parent          父节点句柄
 *\param[in]    buff            PE文件数据
 *\return                       无
 */
void insert_option_head(HWND tree, HTREEITEM parent, UCHAR *buff)
{
    DATA data_item[] = {
        { 2, _T("文件的状态类型                    ")},
        { 1, _T("主链接版本号                      ")},
        { 1, _T("次链接版本号                      ")},
        { 4, _T("代码节的大小                      ")},
        { 4, _T("已初始化数据块的大小              ")},
        { 4, _T("未初始化数据块的大小              ")},
        { 4, _T("程序执行的入口,相对虚拟地址,简称EP")},
        { 4, _T("代码段的起始相对虚拟地址          ")},
        { 4, _T("数据段的起始相对虚拟地址          ")},
        { 4, _T("内存首选装载地址                  ")},
        { 4, _T("节在内存中的对齐值                ")},
        { 4, _T("节在文件中的对齐值                ")},
        { 2, _T("要求最低操作系统的主版本号        ")},
        { 2, _T("要求最低操作系统的次版本号        ")},
        { 2, _T("可执行文件的主版本号              ")},
        { 2, _T("可执行文件的次版本号              ")},
        { 2, _T("要求最低子系统的主版本号          ")},
        { 2, _T("要求最低子系统的次版本号          ")},
        { 4, _T("该成员变量是被保留的              ")},
        { 4, _T("可执行文件装入内存后的总大小      ")},
        { 4, _T("PE头的大小(DOS头,PE头,节表总和)   ")},
        { 4, _T("校验和                            ")},
        { 2, _T("可执行文件的子系统类型            ")},
        { 2, _T("指定DLL文件的属性                 ")},
        { 4, _T("为线程保留的栈大小                ")},
        { 4, _T("为线程已经提交的栈大小            ")},
        { 4, _T("为线程保留的堆大小                ")},
        { 4, _T("为线程已经提交的堆大小            ")},
        { 4, _T("被废弃的成员值                    ")},
        { 4, _T("数据目录项的个数                  ")},
        { 4, _T("导出表虚拟地址                    ")},
        { 4, _T("导出表大小                        ")},
        { 4, _T("导入表虚拟地址                    ")},
        { 4, _T("导入表大小                        ")},
        { 4, _T("资源表虚拟地址                    ")},
        { 4, _T("资源表大小                        ")},
        { 4, _T("异常虚拟地址                      ")},
        { 4, _T("异常大小                          ")},
        { 4, _T("安全证书虚拟地址                  ")},
        { 4, _T("安全证书大小                      ")},
        { 4, _T("重定位表虚拟地址                  ")},
        { 4, _T("重定位表大小                      ")},
        { 4, _T("调试信息虚拟地址                  ")},
        { 4, _T("调试信息大小                      ")},
        { 4, _T("版权所有虚拟地址                  ")},
        { 4, _T("版权所有大小                      ")},
        { 4, _T("全局指针虚拟地址                  ")},
        { 4, _T("全局指针大小                      ")},
        { 4, _T("TLS表虚拟地址                     ")},
        { 4, _T("TLS表大小                         ")},
        { 4, _T("加载配置虚拟地址                  ")},
        { 4, _T("加载配置大小                      ")},
        { 4, _T("绑定导入虚拟地址                  ")},
        { 4, _T("绑定导入大小                      ")},
        { 4, _T("IAT表虚拟地址                     ")},
        { 4, _T("IAT表大小                         ")},
        { 4, _T("延迟导入虚拟地址                  ")},
        { 4, _T("延迟导入大小                      ")},
        { 4, _T("COM虚拟地址                       ")},
        { 4, _T("COM大小                           ")},
        { 4, _T("保留虚拟地址                      ")},
        { 4, _T("保留大小                          ")}
    };

    PIMAGE_DOS_HEADER        dos = (PIMAGE_DOS_HEADER)buff;
    PIMAGE_NT_HEADERS        nt  = (PIMAGE_NT_HEADERS)(buff + dos->e_lfanew);
    PIMAGE_OPTIONAL_HEADER32 opt = (PIMAGE_OPTIONAL_HEADER32)&(nt->OptionalHeader);

    TCHAR txt[128]               = _T("");

    TVINSERTSTRUCT tv            = {0};
    tv.hParent                   = parent;
    tv.hInsertAfter              = TVI_LAST;
    tv.item.mask                 = TVIF_TEXT;
    tv.item.pszText              = txt;

    int    fa                    = (UCHAR*)opt - buff; // OPTION头节点在exe文件中的位置
    TCHAR *name                  = 0;
    UCHAR  size                  = 0;

    for (int i = 0; i < SIZEOF(data_item); i++)
    {
        name = data_item[i].name;
        size = data_item[i].size;

        if (1 == size)  // 1字节数据项
        {
            SP(_T("%04x %s : %02x"), fa, name, *(BYTE*)(buff + fa));
        }
        else if (2 == size)
        {
            SP(_T("%04x %s : %04x"), fa, name, *(WORD*)(buff + fa));
        }
        else
        {
            SP(_T("%04x %s : %08x"), fa, name, *(DWORD*)(buff + fa));
        }

        TreeView_InsertItem(tree, &tv);

        fa += size;
    }
}

/**
 *\brief                        在树中插入DOS,NT,FILE,OPTION头节点和数据项节点
 *\param[in]    tree            树句柄
 *\param[in]    buff            PE文件数据
 *\return                       无
 */
void insert_dosnt_head(HWND tree, UCHAR *buff)
{
    TCHAR txt[128];

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)buff;
    PIMAGE_NT_HEADERS nt  = (PIMAGE_NT_HEADERS)(buff + dos->e_lfanew);

    TVINSERTSTRUCT tv     = {0};
    tv.hParent            = TVI_ROOT;
    tv.hInsertAfter       = TVI_LAST;
    tv.item.mask          = TVIF_TEXT;
    tv.item.pszText       = txt;

    SP(_T("0000 IMAGE_DOS_HEADER"));
    HTREEITEM top = TreeView_InsertItem(tree, &tv);

    SP(_T("%04x IMAGE_NT_HEADERS : %08x"), dos->e_lfanew, nt->Signature);
    TreeView_InsertItem(tree, &tv);

    SP(_T("%04x IMAGE_FILE_HEADER"), dos->e_lfanew + 4);
    HTREEITEM file = TreeView_InsertItem(tree, &tv);

    SP(_T("%04x IMAGE_OPTIONAL_HEADER32"), dos->e_lfanew + 24);
    HTREEITEM option = TreeView_InsertItem(tree, &tv);

    insert_dos_head(tree, top, buff);
    insert_file_head(tree, file, buff);
    insert_option_head(tree, option, buff);
}

/**
 *\brief                        在树中插入段信息数据项
 *\param[in]    tree            树句柄
 *\param[in]    parent          父节点句柄
 *\param[in]    buff            PE文件数据
 *\param[in]    id              SECTION的序号
 *\return                       无
 */
void insert_section_data(HWND tree, HTREEITEM parent, UCHAR *buff, int id)
{
    DATA data_item[] = {
        { 8, _T("节名称                       ")},
        { 4, _T("被实际使用的区块大小         ")},
        { 4, _T("区块的相对虚拟地址           ")},
        { 4, _T("该块在磁盘中所占的大小       ")},
        { 4, _T("该块在磁盘文件中的偏移       ")},
        { 4, _T("在OBJ文件中使用，重定位偏移  ")},
        { 4, _T("行号表的偏移，调试中使用     ")},
        { 2, _T("在OBJ文件中使用，重定位项数目")},
        { 2, _T("行号表中行号的数目           ")},
        { 4, _T("特性                         ")}
    };

    PIMAGE_DOS_HEADER  dos  = (PIMAGE_DOS_HEADER)buff;
    PIMAGE_NT_HEADERS  nt   = (PIMAGE_NT_HEADERS)(buff + dos->e_lfanew);

    TCHAR txt[128]          = _T("");

    TVINSERTSTRUCT tv       = {0};
    tv.hParent              = parent;
    tv.hInsertAfter         = TVI_LAST;
    tv.item.mask            = TVIF_TEXT;
    tv.item.pszText         = txt;

    int fa                  = dos->e_lfanew +
                              sizeof(IMAGE_NT_HEADERS) +
                              id * sizeof(IMAGE_SECTION_HEADER); // 该段头在exe文件中的位置

    TCHAR *name             = 0;
    UCHAR  size             = 0;

    for (int i = 0; i < SIZEOF(data_item); i++)
    {
        name = data_item[i].name;
        size = data_item[i].size;

        if (2 == size)  // 2字节数据项
        {
            SP(_T("%04x %s : %04x"), fa, name, *(WORD*)(buff + fa));
        }
        else if (4 == size)
        {
            SP(_T("%04x %s : %08x"), fa, name, *(DWORD*)(buff + fa));
        }
        else
        {
            SP(_T("%04x %s : %s"), fa, name, g_section_name[id]);
        }

        TreeView_InsertItem(tree, &tv);

        fa += size;
    }
}

/**
 *\brief                        在树中插入SECTION头节点
 *\param[in]  tree              树句柄
 *\param[in]  buff              PE文件数据
 *\return                       无
 */
void insert_section_head(HWND tree, UCHAR *buff)
{
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)buff;
    PIMAGE_NT_HEADERS nt  = (PIMAGE_NT_HEADERS)(buff + dos->e_lfanew);

    TCHAR txt[128]        = _T("");
    HTREEITEM sub         = NULL;

    TVINSERTSTRUCT tv     = {0};
    tv.hParent            = TVI_ROOT;
    tv.hInsertAfter       = TVI_LAST;
    tv.item.mask          = TVIF_TEXT;
    tv.item.pszText       = txt;

    int fa                = dos->e_lfanew + sizeof(IMAGE_NT_HEADERS); // 第1个段头在exe文件中的位置

    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++)
    {
        to_unicode(g_section_name[i], buff + fa); // 将段名转成UNICODE

        SP(_T("%04x IMAGE_SECTION_HEADER %s"), fa, g_section_name[i]);

        sub = TreeView_InsertItem(tree, &tv);

        fa += sizeof(IMAGE_SECTION_HEADER);

        insert_section_data(tree, sub, buff, i);
    }
}

/**
 *\brief                        在树中插入重定位数据块信息节点
 *\param[in]  tree              树句柄
 *\param[in]  parent            树节点句柄
 *\param[in]  *buff             PE文件数据
 *\param[in]  block             数据块头节点
 *\param[in]  section           数据块所在段头节点
 *\param[in]  section_name      数据块所在段名称
 *\param[in]  fa                重定位块头在文件地址
 *\param[in]  va                相对地址
 *\param[in]  block_id          块序号
 *\return                       无
 */
void insert_reloc_block(HWND tree, HTREEITEM parent, UCHAR *buff,
                        PIMAGE_BASE_RELOCATION block,
                        PIMAGE_SECTION_HEADER section,
                        TCHAR *section_name,
                        DWORD fa, DWORD va,
                        int block_id)
{
    TCHAR txt[128]   = _T("");

    TVINSERTSTRUCT tv = {0};
    tv.hParent        = parent;
    tv.hInsertAfter   = TVI_LAST;
    tv.item.mask      = TVIF_TEXT;
    tv.item.pszText   = txt;

    DWORD count       = (block->SizeOfBlock - 8) / 2; // 数据项数量

    SP(_T("%08x %08x 块:%02x 页:%08x 大小:%04x 数量:%02x 节:%08x %08x %s"),
       fa, fa + va, block_id,
       block->VirtualAddress, block->SizeOfBlock, count,
       section->PointerToRawData, section->VirtualAddress, section_name);

    tv.hParent        = TreeView_InsertItem(tree, &tv);

    fa               += sizeof(IMAGE_BASE_RELOCATION); // 重定位数据项在exe文件中的位置

    WORD *list        = (WORD*)(buff + fa);

    WORD  type;
    WORD  addr;
    DWORD addr_fa;
    DWORD addr_va;

    for (UINT j = 0; j < count; j++)
    {
        addr = (*list) & 0x0fff;    // 重定位数据指向的地址,只需要低12位
        type = (*list) >> 12;       // 高4位为类型:0-对齐,3-需要修正的数据

        addr_va = block->VirtualAddress - section->VirtualAddress + addr;
        addr_fa = section->PointerToRawData + addr_va;

        SP(_T("%08x %08x 地址:%04x 类型:%x 节内位置:%08x %08x 数据:%08x"),
           fa, fa + va, addr, type,
           addr_fa, addr_va, *(DWORD*)(buff + addr_fa));

        TreeView_InsertItem(tree, &tv);

        fa += 2;
        list++;
    }
}

/**
 *\brief                        在树中插入重定位信息节点,重定位表/重定位数据块/重定位数据项,共3层
 *\param[in]    tree            树句柄
 *\param[in]    buff            PE文件数据
 *\return                       无
 */
void insert_reloc_table(HWND tree, UCHAR *buff)
{
    PIMAGE_DOS_HEADER        dos          = (PIMAGE_DOS_HEADER)buff;
    PIMAGE_NT_HEADERS        nt           = (PIMAGE_NT_HEADERS)(buff + dos->e_lfanew);
    PIMAGE_OPTIONAL_HEADER32 opt          = (PIMAGE_OPTIONAL_HEADER32)&(nt->OptionalHeader);
    PIMAGE_SECTION_HEADER    section_list = (PIMAGE_SECTION_HEADER)(nt + 1);
    PIMAGE_SECTION_HEADER    section;
    PIMAGE_BASE_RELOCATION   block;

    TCHAR txt[128]                        = _T("");
    HTREEITEM item                        = NULL;

    TVINSERTSTRUCT tv                     = {0};
    tv.hParent                            = TVI_ROOT;
    tv.hInsertAfter                       = TVI_LAST;
    tv.item.mask                          = TVIF_TEXT;
    tv.item.pszText                       = txt;

    DWORD fa;                                           // 重定位表在exe文件中的位置
    DWORD va = opt->DataDirectory[5].VirtualAddress;    // 重定位表在内存中的位置

    if (0 == va)
    {
        return; // 没有重定位表
    }

    int section_id = search_section(nt, va);    // 查找重定位表所在段,一般在.rdata

    if (section_id < 0)
    {
        return; // 没有重定位表
    }

    section = &section_list[section_id];

    fa = section->PointerToRawData + opt->DataDirectory[5].VirtualAddress - section->VirtualAddress;

    va -= fa;   // 内存位置与文件位置的偏移

    SP(_T("%08x %08x 重定位 所在节:%08x %08x %s"), fa, fa + va,
       section->PointerToRawData, section->VirtualAddress, g_section_name[section_id]);

    item = TreeView_InsertItem(tree, &tv);

    for (int i = 0; ; i++)
    {
        block = (PIMAGE_BASE_RELOCATION)(buff + fa); // 块数据长度不定

        if (0 == block->VirtualAddress || 0 == block->SizeOfBlock)
        {
            break;
        }

        // 查找重定位数据块所在的段
        section_id = search_section(nt, block->VirtualAddress);

        if (section_id < 0)
        {
            MessageBox(NULL, _T("search_section"), g_title, MB_OK);
            return; // 出错
        }

        insert_reloc_block(tree, item, buff, block,
                           &section_list[section_id], g_section_name[section_id],
                           fa, va, i);

        fa += block->SizeOfBlock;
    }
}

/**
 *\brief                        在树中插入导出表函数名称信息节点
 *\param[in]  tree              树句柄
 *\param[in]  parent            树节点句柄
 *\param[in]  *buff             PE文件数据
 *\param[in]  section           头节点
 *\param[in]  export            头节点
 *\param[in]  name_addr_list_addr   函数名指针列表地址
 *\param[in]  va                相对地址
 *\return                       无
 */
void insert_export_name(HWND tree, HTREEITEM parent, UCHAR *buff,
                        PIMAGE_SECTION_HEADER section,
                        PIMAGE_EXPORT_DIRECTORY export,
                        DWORD name_addr_list_addr,
                        DWORD va)
{
    TCHAR txt[128]    = _T("");

    TVINSERTSTRUCT tv = {0};
    tv.hParent        = parent;
    tv.hInsertAfter   = TVI_LAST;
    tv.item.mask      = TVIF_TEXT;
    tv.item.pszText   = txt;

    // 导出函数名列表在exe文件中的位置
    DWORD fa          = section->PointerToRawData + name_addr_list_addr - section->VirtualAddress;
    DWORD *list       = (DWORD*)(buff + fa);
    DWORD name_va     = 0;
    DWORD name_fa     = 0;

    for (UINT i = 0; i < export->NumberOfNames; i++)
    {
        name_va = list[i];
        name_fa = section->PointerToRawData + name_va - section->VirtualAddress;

        SP(_T("%08x %08x 名称:%08x %08x "), fa, fa + va, name_fa, name_va);

        to_unicode(txt, buff + name_fa);

        TreeView_InsertItem(tree, &tv);

        fa += 4;
    }
}

/**
 *\brief                        在树中插入导出表函数ID信息节点
 *\param[in]    tree            树句柄
 *\param[in]    parent          树节点句柄
 *\param[in]    buff            PE文件数据
 *\param[in]    section         头节点
 *\param[in]    export          头节点
 *\param[in]    id_list_addr    函数ID列表地址
 *\param[in]    va              相对地址
 *\return                       无
 */
void insert_export_id(HWND tree, HTREEITEM parent, UCHAR *buff,
                      PIMAGE_SECTION_HEADER section,
                      PIMAGE_EXPORT_DIRECTORY export,
                      DWORD id_list_addr,
                      DWORD va)
{
    TCHAR txt[128];
    TVINSERTSTRUCT tv = {0};
    tv.hParent        = parent;
    tv.hInsertAfter   = TVI_LAST;
    tv.item.mask      = TVIF_TEXT;
    tv.item.pszText   = txt;

    // 导出函数ID列表在exe文件中的位置
    DWORD fa          = section->PointerToRawData + id_list_addr - section->VirtualAddress;
    WORD *list        = (WORD*)(buff + fa);

    for (UINT i = 0; i < export->NumberOfFunctions; i++)
    {
        // Base函数序号开始值
        SP(_T("%08x %08x ID:%04x 序号:%04x"), fa, fa + va, list[i], export->Base + list[i]);

        TreeView_InsertItem(tree, &tv);

        fa += 4;
    }
}

/**
 *\brief                        在树中插入导出表函数信息节点
 *\param[in]  tree              树句柄
 *\param[in]  parent            树节点句柄
 *\param[in]  *buff             PE文件数据
 *\param[in]  section           头节点
 *\param[in]  export            头节点
 *\param[in]  func_addr_list_addr   函数ID列表地址
 *\param[in]  va                相对地址
 *\return                       无
 */
void insert_export_func(HWND tree, HTREEITEM parent, UCHAR *buff,
                        PIMAGE_SECTION_HEADER section,
                        PIMAGE_EXPORT_DIRECTORY export,
                        DWORD func_addr_list_addr,
                        DWORD va)
{
    TCHAR txt[128]    = _T("");

    TVINSERTSTRUCT tv = {0};
    tv.hParent        = parent;
    tv.hInsertAfter   = TVI_LAST;
    tv.item.mask      = TVIF_TEXT;
    tv.item.pszText   = txt;

    // 导出函数指针列表在exe文件中的位置
    DWORD fa          = section->PointerToRawData + func_addr_list_addr - section->VirtualAddress;
    DWORD *list       = (DWORD*)(buff + fa);

    for (UINT i = 0; i < export->NumberOfNames; i++)
    {
        SP(_T("%08x %08x 函数地址:%08x"), fa, fa + va, list[i]);

        TreeView_InsertItem(tree, &tv);

        fa += 4;
    }
}

/**
 *\brief                        在树中插入导出表信息节点
 *\param[in]    tree            树句柄
 *\param[in]    buff            PE文件数据
 *\return                       无
 */
void insert_export_table(HWND tree, UCHAR *buff)
{
    DATA data_item[] = {
        { 4, _T("主链接版本号                      ")},
        { 4, _T("文件创建时间                      ")},
        { 2, _T("主链接版本号                      ")},
        { 2, _T("次链接版本号                      ")},
        { 4, _T("导出表文件名地址                  ")},
        { 4, _T("导出函数的起始序号                ")},
        { 4, _T("所有的导出函数的个数              ")},
        { 4, _T("以名字导出的函数的个数            ")},
        { 4, _T("导出的函数表地址                  ")},
        { 4, _T("导出的函数名称表地址              ")},
        { 4, _T("导出函数序号表地址                ")}
    };

    PIMAGE_DOS_HEADER        dos     = (PIMAGE_DOS_HEADER)buff;
    PIMAGE_NT_HEADERS        nt      = (PIMAGE_NT_HEADERS)(buff + dos->e_lfanew);
    PIMAGE_OPTIONAL_HEADER32 opt     = (PIMAGE_OPTIONAL_HEADER32)&(nt->OptionalHeader);
    PIMAGE_SECTION_HEADER    section = (PIMAGE_SECTION_HEADER)(nt + 1);
    PIMAGE_EXPORT_DIRECTORY  export;

    DWORD fa;                                           // 导出表在exe文件中的位置
    DWORD va = opt->DataDirectory[0].VirtualAddress;    // 导出表在内存中的位置

    if (0 == va)
    {
        return; // 没有导出表
    }

    int section_id = search_section(nt, va);    // 查找导出表数据所在节,一般在.edata

    if (section_id < 0)
    {
        return;
    }

    section = &section[section_id];

    fa = section->PointerToRawData + opt->DataDirectory[0].VirtualAddress - section->VirtualAddress;

    va -= fa;   // 内存位置与文件位置的偏移

    TCHAR txt[128]    = _T("");
    HTREEITEM sub     = NULL;
    HTREEITEM subsub  = NULL;

    TVINSERTSTRUCT tv = {0};
    tv.hParent        = TVI_ROOT;
    tv.hInsertAfter   = TVI_LAST;
    tv.item.mask      = TVIF_TEXT;
    tv.item.pszText   = txt;

    SP(_T("%08x %08x 导出表 所在节:%08x %08x %s"), fa, fa + va,
       section->PointerToRawData, section->VirtualAddress, g_section_name[section_id]);

    sub = TreeView_InsertItem(tree, &tv);

    export = (PIMAGE_EXPORT_DIRECTORY)(buff + fa); // 导出表头节点

    DWORD  data;
    TCHAR *name;
    UCHAR  size;

    for (int i = 0; i < SIZEOF(data_item); i++)
    {
        name = data_item[i].name;
        size = data_item[i].size;

        if (2 == size)
        {
            SP(_T("%08x %08x %s :%04x"), fa, fa + va, name, *(WORD*)(buff + fa));
        }
        else
        {
            data = *(DWORD*)(buff + fa);
            SP(_T("%08x %08x %s :%08x "), fa, fa + va, name, data);
        }

        if (4 == i) // 名字
        {
            char *name = (char*)(buff + section->PointerToRawData + export->Name -
                                section->VirtualAddress);

            to_unicode(txt, name);
        }

        tv.hParent = sub;
        subsub = TreeView_InsertItem(tree, &tv);

        if (8 == i) // 导出函数表
        {
            insert_export_func(tree, subsub, buff, section, export, data, va);
        }
        else if (9 == i) // 导出函数名表
        {
            insert_export_name(tree, subsub, buff, section, export, data, va);
        }
        else if (10 == i) // 导出函数序号表
        {
            insert_export_id(tree, subsub, buff, section, export, data, va);
        }

        fa += size;
    }
}

/**
 *\brief                        在树中插入导入表函数信息节点
 *\param[in]    tree            树句柄
 *\param[in]    parent          树节点句柄
 *\param[in]    *buff           PE文件数据
 *\param[in]    section         头节点
 *\param[in]    thunk_list_addr 列表地址
 *\param[in]    va              相对地址
 *\return                       无
 */
void insert_import_thunk(HWND tree, HTREEITEM parent, UCHAR *buff,
                         PIMAGE_SECTION_HEADER section,
                         DWORD thunk_list_addr,
                         DWORD va)
{
    TCHAR txt[512]           = _T("");
    HTREEITEM item            = NULL;

    TVINSERTSTRUCT tv         = {0};
    tv.hInsertAfter           = TVI_LAST;
    tv.item.mask              = TVIF_TEXT;
    tv.item.pszText           = txt;

    DWORD fa                  = section->PointerToRawData +
                                thunk_list_addr -
                                section->VirtualAddress;    // 导入表thunk列表在exe文件中的位置

    PIMAGE_THUNK_DATA32 thunk = (PIMAGE_THUNK_DATA32)(buff + fa);

    DWORD type;
    DWORD value;
    DWORD name_fa;
    PIMAGE_IMPORT_BY_NAME name_data;

    while (thunk->u1.Function != 0)
    {
        type = thunk->u1.Function >> 31;        // 最高位为导入类型:0-按名称导入,1-按序号导入
        value = thunk->u1.Function & 0xEFFFFFFF;

        SP(_T("%08x %08x 类型:%x 值:%08x"), fa, fa + va, type, value);
        tv.hParent = parent;
        item = (HTREEITEM)TreeView_InsertItem(tree, &tv);

        if (0 == type) // 0-按名称导入,存的是函数名地址. 1-按序号导入,存的是序号
        {
            name_fa = section->PointerToRawData + value - section->VirtualAddress;

            name_data = (PIMAGE_IMPORT_BY_NAME)(buff + name_fa);

            SP(_T("%08x %08x id:%04x 名称:"), name_fa, name_fa + va, name_data->Hint);

            to_unicode(txt, name_data->Name);

            tv.hParent = item;
            TreeView_InsertItem(tree, &tv);
        }

        thunk++;
        fa += sizeof(IMAGE_THUNK_DATA32);
    }
}

/**
 *\brief                        在树中插入导入表库信息节点
 *\param[in]    tree            树句柄
 *\param[in]    parent          树节点句柄
 *\param[in]    *buff           PE文件数据
 *\param[in]    import          头节点
 *\param[in]    section         头节点
 *\param[in]    fa              文件地址
 *\param[in]    va              相对地址
 *\return                       无
 */
void insert_import_library(HWND tree, HTREEITEM parent, UCHAR *buff,
                           PIMAGE_IMPORT_DESCRIPTOR import,
                           PIMAGE_SECTION_HEADER section,
                           DWORD fa, DWORD va)
{
    DATA data_item[] = {
        { 4, _T("输入名称表的地址                  ")},
        { 4, _T("文件创建时间                      ")},
        { 4, _T("被转向API的索引                   ")},
        { 4, _T("库名称地址                        ")},
        { 4, _T("输入地址表的地址                  ")}
    };

    TCHAR txt[512]    = _T("");
    HTREEITEM item    = NULL;

    TVINSERTSTRUCT tv = {0};
    tv.hParent        = parent;
    tv.hInsertAfter   = TVI_LAST;
    tv.item.mask      = TVIF_TEXT;
    tv.item.pszText   = txt;

    // 库名称地址在exe文件中的位置
    int lib_name_fa   = section->PointerToRawData + import->Name - section->VirtualAddress;

    SP(_T("%08x %08x 库名称地址:%08x %08x "), fa, fa + va, lib_name_fa, import->Name);

    to_unicode(txt, buff + lib_name_fa);

    tv.hParent = TreeView_InsertItem(tree, &tv);

    DWORD *data = (DWORD*)(buff + fa);
    TCHAR *name;
    UCHAR  size;

    for (int i = 0; i < SIZEOF(data_item); i++)
    {
        name = data_item[i].name;
        size = data_item[i].size;

        SP(_T("%08x %08x %s :%08x"), fa, fa + va, name, *data);

        item = TreeView_InsertItem(tree, &tv);

        if (i == 0)
        {
            insert_import_thunk(tree, item, buff, section, import->OriginalFirstThunk, va);
        }
        else if (i == 4)
        {
            insert_import_thunk(tree, item, buff, section, import->FirstThunk, va);
        }

        data++;
        fa += size;
    }
}

/**
 *\brief                        在树中插入导出表信息节点
 *\param[in]    tree            树句柄
 *\param[in]    buff            PE文件数据
 *\return                       无
 */
void insert_import_table(HWND tree, UCHAR *buff)
{
    PIMAGE_DOS_HEADER        dos     = (PIMAGE_DOS_HEADER)buff;
    PIMAGE_NT_HEADERS        nt      = (PIMAGE_NT_HEADERS)(buff + dos->e_lfanew);
    PIMAGE_OPTIONAL_HEADER32 opt     = (PIMAGE_OPTIONAL_HEADER32)&(nt->OptionalHeader);
    PIMAGE_SECTION_HEADER    section = (PIMAGE_SECTION_HEADER)(nt + 1);
    PIMAGE_IMPORT_DESCRIPTOR import;

    DWORD fa;                                           // 导入表在exe文件中的位置
    DWORD va = opt->DataDirectory[1].VirtualAddress;    // 导入表在内存中的位置

    if (0 == va)
    {
        return; // 没有导入表
    }


    int section_id = search_section(nt, va);    // 查找导出表数据所在节,一般在.rdata

    if (section_id < 0)
    {
        return;
    }

    section = &section[section_id];

    fa = section->PointerToRawData + opt->DataDirectory[1].VirtualAddress - section->VirtualAddress;

    va -= fa;   // 内存位置与文件位置的偏移

    TCHAR txt[512]    = _T("");
    HTREEITEM item    = NULL;

    TVINSERTSTRUCT tv = {0};
    tv.hParent        = TVI_ROOT;
    tv.hInsertAfter   = TVI_LAST;
    tv.item.mask      = TVIF_TEXT;
    tv.item.pszText   = txt;


    SP(_T("%08x %08x 导入表 所在节:%08x %08x %s"), fa, fa + va,
       section->PointerToRawData, section->VirtualAddress, g_section_name[section_id]);

    item = TreeView_InsertItem(tree, &tv);

    import = (PIMAGE_IMPORT_DESCRIPTOR)(buff + fa); // 导入表头节点

    while (import->OriginalFirstThunk != 0)
    {
        insert_import_library(tree, item, buff, import, section, fa, va);
        fa += sizeof(IMAGE_IMPORT_DESCRIPTOR);
        import++;
    }
}

/**
 *\brief                        在树中插入节点
 *\param[in]    tree            树句柄
 *\param[in]    buff            数据
 *\return                       无
 */
void insert_tv_item(HWND tree, UCHAR* buff)
{
    TreeView_DeleteAllItems(tree);
    insert_dosnt_head(tree, buff);
    insert_section_head(tree, buff);
    insert_export_table(tree, buff);
    insert_import_table(tree, buff);
    insert_reloc_table(tree, buff);
}

/**
 *\brief                        更新数据
 *\param[in]    name            文件名称
 *\return                       无
 */
void update_treeview(TCHAR *name)
{
    FILE *fp = NULL;
    _tfopen_s(&fp, name, _T("rb"));

    if (NULL == fp)
    {
        TCHAR txt[128];
        SP(_T("open %s error %d"), name, GetLastError());
        MessageBox(NULL, txt, g_title, MB_ICONEXCLAMATION);
    }

    fseek(fp, 0, SEEK_END);
    UINT size = ftell(fp);
    UCHAR *buff = malloc(size);
    fseek(fp, 0, SEEK_SET);
    fread(buff, 1, size, fp);
    fclose(fp);

    if (buff[0] != 'M' || buff[1] != 'Z')
    {
        TCHAR txt[128];
        SP(_T("this %s is not pe file"), name);
        MessageBox(NULL, txt, g_title, MB_ICONEXCLAMATION);
        return;
    }

    insert_tv_item(g_tree, buff);
    free(buff);
}

/**
 *\brief                        拖拽文件
 *\param[in]    wnd             窗体句柄
 *\param[in]    w               拖拽句柄
 *\return                       无
 */
void on_dropfiles(HWND wnd, WPARAM w)
{
    HDROP drop = (HDROP)w;

    TCHAR name[512];
    DragQueryFile(drop, 0, name, MAX_PATH);
    DragFinish(drop);

    SetWindowText(wnd, name);
    update_treeview(name);
}

/**
 *\brief                        创建消息处理函数
 *\param[in]    wnd             窗体句柄
 *\return                       无
 */
void on_create(HWND wnd)
{
    g_tree = CreateWindow(WC_TREEVIEW,
                          _T("Tree View"),
                          WS_CHILD | WS_VISIBLE | TVS_HASLINES| TVS_HASBUTTONS |
                          TVS_LINESATROOT | WS_EX_ACCEPTFILES,
                          0, 0,
                          100, 100,
                          wnd,
                          NULL,
                          NULL,
                          NULL);

    SendMessage(g_tree, WM_SETFONT, (WPARAM)g_font, (LPARAM)TRUE);

    DragAcceptFiles(wnd, TRUE); // 属性WS_EX_ACCEPTFILES
}

/**
 *\brief                        窗体类消息处理回调函数
 *                              当用户点击窗体上的关闭按钮时,
 *                              系统发出WM_CLOSE消息,DefWindowProc内执行DestroyWindow关闭窗口,DestroyWindow内发送WM_DESTROY消息,
 *                              需要自己调用PostQuitMessage关闭应用程序,PostQuitMessage内发出WM_QUIT消息来关闭消息循环
 *\param[in]    wnd             窗体句柄
 *\param[in]    msg             消息ID
 *\param[in]    w               消息参数
 *\param[in]    l               消息参数
 *\return                       消息处理结果，它与发送的消息有关
 */
LRESULT CALLBACK window_proc(HWND wnd, UINT msg, WPARAM w, LPARAM l)
{
    switch(msg)
    {
        case WM_CREATE:     on_create(wnd);                                         break;
        case WM_DROPFILES:  on_dropfiles(wnd, w);                                   break;
        case WM_SIZE:       MoveWindow(g_tree, 0, 0, LOWORD(l), HIWORD(l), TRUE);   break;
        case WM_DESTROY:    PostQuitMessage(0);                                     break;
    }

    return DefWindowProc(wnd, msg, w, l);
}

/**
 *\brief                        窗体类程序主函数
 *\param[in]    hInstance       当前实例句柄
 *\param[in]    hPrevInstance   先前实例句柄
 *\param[in]    lpCmdLine       命令行参数
 *\param[in]    nCmdShow        显示状态(最小化,最大化,隐藏)
 *\return                       程序返回值
 */
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
    // 窗体大小
    int cx = 800;
    int cy = 600;

    // 树控件字体
    LOGFONT font = { 18, 8, 0, 0, 400, 0, 0, 0, DEFAULT_CHARSET, 0, 0, 0, 0, _T("Courier New") };
    g_font = CreateFontIndirect(&font);

    // 窗体类
    WNDCLASS wc = { CS_HREDRAW | CS_VREDRAW, window_proc, 0, 0, hInstance, 0, 0, 0, 0, g_title };
    RegisterClass(&wc);

    // 创建窗体
    HWND wnd = CreateWindow(wc.lpszClassName,                           // 类名称
                            g_title,                                    // 窗体名称
                            WS_OVERLAPPEDWINDOW,                        // 窗体属性
                            (GetSystemMetrics(SM_CXSCREEN) - cx) / 2,   // 窗体位置
                            (GetSystemMetrics(SM_CYSCREEN) - cy) / 2,   // 窗体居中
                            cx, cy,                                     // 窗体大小
                            NULL,                                       // 父窗句柄
                            NULL,                                       // 菜单句柄
                            hInstance,                                  // 实例句柄
                            NULL);                                      // 参数,给WM_CREATE的lParam的CREATESTRUCT

    // 显示窗体
    ShowWindow(wnd, SW_SHOWNORMAL);

    // 重绘窗体
    UpdateWindow(wnd);

    // 消息体
    MSG msg;

    // 消息循环,从消息队列中取得消息,只到WM_QUIT时退出
    while (GetMessage(&msg, NULL, 0, 0))
    {
        TranslateMessage(&msg); // 将WM_KEYDOWN和WM_KEYUP转换为一条WM_CHAR消息
        DispatchMessage(&msg);  // 分派消息到窗口,内部调用窗体消息处理回调函数
    }

    return (int)msg.lParam;
}