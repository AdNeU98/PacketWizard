include /usr/local/etc/PcapPlusPlus.mk

# All Target
all:
	g++ $(PCAPPP_BUILD_FLAGS) $(PCAPPP_INCLUDES) -c main.cpp C_packetParser.cpp C_packetFilter.cpp C_pcapWriter.cpp
	g++ $(PCAPPP_LIBS_DIR)  -o parsePCAP main.o C_packetParser.o C_packetFilter.o C_pcapWriter.o $(PCAPPP_LIBS)

# Clean Target
clean:
	rm main.o
	rm parsePCAP