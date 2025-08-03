src = erktpass.c
target = $(basename $(src))

all:
	gcc $(src) -Wall -g -o $(target)

clean:
	rm -rf $(target)
