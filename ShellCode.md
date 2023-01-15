### shellcode编码
>为什么要对 shellcode 编码？ 在很多漏洞利用场景中，shellcode 的内容将会受到限制：
首先，所有的字符串函数都会对 NULL 字节进行限制。通常我们需要选择特殊的指令来避免在 shellcode 中直接出现 NULL 字节（byte，ASCII 函数）或字（word，Unicode 函数）；
其次，有些函数还会要求 shellcode 必须为可见字符的 ASCII 值或 Unicode 值。在这种限制 较多的情况下，如果仍然通过挑选指令的办法控制 shellcode 的值的话，将会给开发带来很大困 难。毕竟用汇编语言写程序就已经不那么容易了；
最后，除了以上提到的软件自身的限制之外，在进行网络攻击时，基于特征的 IDS 系统往往也会对常见的 shellcode 进行拦截。
那么如何绕过以上限制呢？
我们可以先专心完成 shellcode 的逻辑，然后使用编码技术对 shellcode 进行编码，使其内容达到限制的要求，最后再精心构造十几个字节的解码程序，放在 shellcode 开始执行的地方。
当 exploit 成功时，shellcode 顶端的解码程序首先运行，它会在内存中将真正的 shellcode 还原成原来的样子，然后执行之。这种对 shellcode 编码的方法和软件加壳的原理非常类似。
