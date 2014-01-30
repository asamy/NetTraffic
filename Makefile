BIN = netraffic

CC = gcc
BTYPE = -O2
CFLAGS = -static-libgcc -Wall -Wno-unused-result $(BTPYE)
LIBS = -s -lPacket -lwpcap

SRC = capture.c main.c
OBJ  = obj
OBJS = $(SRC:%.c=$(OBJ)/%.o)

all: $(BIN)
clean:
	$(RM) $(OBJ)/*.o
	$(RM) $(BIN)

${BIN}: $(OBJ) $(OBJS)
	@echo "  LD     $@"
	@$(CC) ${CFLAGS} -o $@ $(OBJS) ${LIBS}

${OBJ}/%.o: %.c
	@echo "  CC     $<"
	@$(CC) -c $(CFLAGS) -o $@ $<

$(OBJ):
	@mkdir -p $(OBJ)
