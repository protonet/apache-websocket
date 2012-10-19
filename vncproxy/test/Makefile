OUTPUT = ../build/guactest
TARGET = guactest

# Specify the list of objects, relative to the OUTPUT directory
OBJS = guactest.o utils.o
#DEBUG = -g -DDEBUG_COND_WAIT
#DEBUG = -g -DDEBUG_RBTREES
DEBUG = -g

CFLAGS = -Wall -c $(DEBUG) -I. -lpthread
LFLAGS = -Wall $(DEBUG) -lpthread
CC = gcc

IMGS = daisy-glass-art.png dandelions-2.png red-tulips-flower.png single-pixel.png
IMGH = $(OUTPUT)/image.h

# Work out the build directory variants
BUILDOBJECTS := $(patsubst %o, $(OUTPUT)/%o, $(OBJS))

# Get the list of output directories
BUILDDIRS := $(sort $(foreach dir,$(BUILDOBJECTS),$(shell dirname $(dir))))

# First target for bare "make"
all: $(OUTPUT)/$(TARGET)

clean:
	@/bin/rm -rf $(OUTPUT)/*

$(OUTPUT)/$(TARGET): $(BUILDOBJECTS)
	@mkdir -p $(OUTPUT)
	$(CC) ${BUILDOBJECTS} ${LFLAGS} -o $(OUTPUT)/$(TARGET)

# automatic dependencies - pull in dependency info for *existing* .o files
-include $(BUILDOBJECTS:.o=.d)

# autogenerate dependencies after a successful compilation
$(OUTPUT)/%.o: %.c $(IMGH)
	@mkdir -p $(BUILDDIRS)
	$(CC) -c $(CFLAGS) -MMD -MP -MF"$(OUTPUT)/$*.d" -o $@ $<
	@mv -f $(OUTPUT)/$*.d $(OUTPUT)/$*.d.tmp
	@sed -e 's|.*:|$(OUTPUT)/$*.o:|' < $(OUTPUT)/$*.d.tmp > $(OUTPUT)/$*.d
	@sed -e 's/.*://' -e 's/\\$$//' < $(OUTPUT)/$*.d.tmp | fmt -1 | \
	  sed -e 's/^ *//' -e 's/$$/:/' >> $(OUTPUT)/$*.d
	@rm -f $(OUTPUT)/$*.d.tmp

# generate a .h file containing the images
$(IMGH): $(IMGS) makeimages
	@mkdir -p $(BUILDDIRS)
	./makeimages $(IMGS) > $(IMGH)

.PHONY: all clean

