APXS=apxs
APXS_FLAGS=-Wc,-Wall -Wc,-g -Wc,-O3 -Wl,-lcurl

TARGET=mod_upload.slo
SRC=mod_upload.c
HEADERS=

all: $(TARGET)

$(TARGET): $(SRC) $(HEADERS)
	$(APXS) -c $(APXS_FLAGS) $(SRC)

install: $(TARGET)
	sudo $(APXS) -i -c $(APXS_FLAGS) $(SRC)

clean:
	@rm $(TARGET:slo=*o) $(TARGET:slo=*a)
