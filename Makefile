# Compiler
CC = gcc
# Compiler flags
CFLAGS = -g #-Wall -Wmissing-prototypes -Werror -pedantic
# Compiler optimisation level
CCOPT = -O3
# Linker flags
LDFLAGS = -lgmp -lm

# *********************************************************
#  Folders & files variable
# *********************************************************

# executable name
EXEC = rsa
# $(BIN)ary folder
BIN = .
# $(SRC) folder
SRC = .
# objects need by everyone
OBJECTS = $(BIN)/prime.o rsa.o
# objects for executable
EXEC_OBJECTS = $(BIN)/main.o $(OBJECTS)

# *********************************************************
#  Now, the command
# *********************************************************

all : $(BIN)/$(EXEC)
	@echo "Compilation done."

$(BIN)/$(EXEC) : $(EXEC_OBJECTS)
	$(CC) $^ -o $@ $(LDFLAGS)

$(BIN)/%.o : $(SRC)/%.c
	$(CC) $(CCOPT) -c $< -o $@ $(CFLAGS)

indent :
	indent -orig -nut main.c
	indent -orig -nut rsa.c
	indent -orig -nut prime.c

clean :
	rm -rf $(BIN)/$(EXEC) $(BIN)/*.o
