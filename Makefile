## [M1: point 1]
#  Explain following in here
#  MODULE is a varaible that will be expanded to "ex3" further in the makefile.
#  ...
MODULE	 = perftop

## [M2: point 1]
#  Explain following in here
#  "obj-m" is a varaible that will takes its own value and add the another variable value to it. Here the other variable that will be
#  appended to the value to "obj-m" will be $(MODULE).o $(MODULE) will expand to "ex3" as mentioned above. 
#  ex3.o thus will be built as a module (denoted by obj-m) 
#  ...
obj-m += $(MODULE).o

## [M3: point 1]
#  Explain following in here
#  KERNELDIR variable is used to store the path of the kbuild system i.e. Makefile used by the current kernel to compile external modules.
#  Thus, KERNELDIR will expand to the Makefile of the current kernel which bu default is present in lib/modules/"current kernel version"/build.
#  uname -r will hold the name and information of the current kernel. 
#  ...
KERNELDIR ?= /lib/modules/$(shell uname -r)/build

## [M4: point 1]
#  Explain following in here
#  "shell pwd" will return the current working directory which will be stored in the variable PWD.
#  ...
PWD := $(shell pwd)

## [M5: point 1]
#  Explain following in here
#  all: denotes the target that will be built when "make" is called without specifying any target. 
#  ...
all: $(MODULE)


## [M6: point 1]
#  Explain following in here
#  All the ".o" files depend on ".c" files. For every ".o" file the follwoing 2 commands will be invoked. 
#  echo is used to print each line of the recipe before make. '@' will suppress printing during make.
#  The compiler is invoked for the target files here.
#  ...
%.o: %.c
	@echo "  CC      $<"
	@$(CC) -c $< -o $@

## [M7: point 1]
#  Explain following in here
#  $(MAKE) gets replaced by "make"
#  $(KERNELDIR) & $(PWD) are expanded as mentioned above.
#  -C will change the build directory to the path following "-C" before executing make. 
#  M=$(PWD) mentions where the module is present
#  Thus the actual compilation of the module is being done here. 
#  ...
$(MODULE):
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules

## [M8: point 1]
#  Explain following in here
#  When "make clean" is called this command will be executed. 
#  ...
clean:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) clean
