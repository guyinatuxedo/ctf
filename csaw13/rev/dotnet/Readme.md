Let's take a look at the binary:

```
$	file dotPeek32.2017.1.3.exe 
dotPeek32.2017.1.3.exe: PE32 executable (GUI) Intel 80386, for MS Windows
```

So we can see that it is a 32 but .NET executable. Forutantely for us, we will be able to decompile the executable straight to the original source code. I did this using this open sourced decompiler:

```
https://www.jetbrains.com/decompiler/
```

When we run the executable in Windows, we see that it is asking for a passcode to unlock the prize. When we pop the executable into the .NET decompiler, we can clearly see what it is asking for:
```
namespace dotnetreversingchallenge
{
  internal class aClass
  {
    private static void Main(string[] args)
    {
      Console.WriteLine("Greetings challenger! Step right up and try your shot at gaining the flag!");
      Console.WriteLine("You'll have to know the pascode to unlock the prize:");
      long int64 = Convert.ToInt64(Console.ReadLine());
      long num1 = 53129566096;
      long num2 = 65535655351;
      if ((int64 ^ num1) == num2)
        Console.WriteLine("yay");
      else
        Console.WriteLine("Incorrect, try again!");
```

So we can see that it is prompting us for inpu that will be converted into an integer. We can see that later it takes the integer `53129566096` and xors it against our input, then checks to see if it is equal to `65535655351`. So we can just xor `53129566096` and `65535655351` together since xoring is reversible, and that should be the integer needed to pass the check:

```
$	python
Python 2.7.13 (default, Jan 19 2017, 14:48:08) 
[GCC 6.3.0 20170118] on linux2
Type "help", "copyright", "credits" or "license" for more information.
>>> 53129566096 ^ 65535655351
13371337255
```

So when we run the binary and input the integer `13371337255` we get the flag `flag{I'll create a GUI interface using visual basic...see if I can track an IP address.}`.
