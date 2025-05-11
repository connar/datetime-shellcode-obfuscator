# datetime-shellcode-loader
A tool to generate C code that hides shellcode in datetime formats

## Tree 
In the `final_python` folder, you will find the code that encodes and decodes shellcode into/from datetime strings, in case you want to add/modify it and try something new yourself.    
In the `final_c` folder, you will find the code that encodes and decodes shellcode into/from datetime strings, in case you want to add/modify it and try something new yourself.  
In the `final` folder, you will find the python script that generates a `.c` template and the corresponding `.exe`. Basically you just hardcode your shellcode there, and you get an executable with only the deobfuscation scheme and the hardcoded datetime strings.  

## Explanation of the tool
For an explanation of the tool, you can see a blogpost I made about it on my [blog](https://connar.github.io/posts/customshellcodeloader/)
