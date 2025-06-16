#define WIN32
#include <stdint.h>
#include <iostream>
#include <vector>
#include <map>
#include <fstream>
#include <iomanip>
#include <cstdint>
#include <filesystem>
#include <pcap.h>
#include <pcap/usb.h>

#define MAX_MAP_ENTRIES 128
#define MAX_DATA_BRAM 4096

std::string pcap_capture_file = "D:\\dev\\archives\\arcade-controller-2.pcap";
std::string file_data_coe = "usb_packet_data.coe";
std::string file_map_coe = "usb_packet_map.coe";

#pragma pack(push, 1)
struct usb_packet_map_entry {
	uint8_t slot_id;
	uint8_t endpoint_id;
	uint8_t bm_request_type;
	uint8_t b_request;
	
	uint16_t w_value;
	uint16_t w_index;

	uint16_t data_length;
	uint16_t bram_address;
};

usb_packet_map_entry map_entries[MAX_MAP_ENTRIES];
#pragma pack(pop)

struct usb_packet_entry {
	usb_packet_map_entry *map_entry;
	void* data;
};

struct device_map {
	int bus_num;
	int dev_num;
	
	int slot_id;
};

std::vector<device_map> devices;
std::vector<usb_packet_entry> entries;
std::vector<uint32_t> data;

int map_entry_index = 0;

static void new_entry(
	uint8_t slot_id,
	uint8_t endpoint_id,
	uint8_t bm_request_type,
	uint8_t b_request,
	uint16_t w_value,
	uint16_t w_index,
	uint16_t data_length,
	uint16_t bram_address,
	void* pointer
) {

	for (usb_packet_entry& entry : entries) {
		if (entry.map_entry->slot_id != slot_id) continue;
		if (entry.map_entry->endpoint_id != endpoint_id) continue;
		if (entry.map_entry->bm_request_type != bm_request_type) continue;
		if (entry.map_entry->b_request != b_request) continue;
		if (entry.map_entry->w_value != w_value) continue;
		if (entry.map_entry->w_index != w_index) continue;
		if (entry.map_entry->data_length >= data_length) continue;
		printf("data update %d -> %d!\n", entry.map_entry->data_length, data_length);
		entry.data = pointer;
		entry.map_entry->data_length = data_length;
		return;
	}

	usb_packet_map_entry map_entry = {};
	map_entry.slot_id = slot_id;
	map_entry.endpoint_id = endpoint_id;
	map_entry.bm_request_type = bm_request_type;
	map_entry.b_request = b_request;
	map_entry.w_value = w_value;
	map_entry.w_index = w_index;
	map_entry.data_length = data_length;
	map_entry.bram_address = bram_address;
	map_entries[map_entry_index] = map_entry;
	usb_packet_entry entry = {};
	entry.map_entry = &map_entries[map_entry_index];
	entry.data = pointer;
	entries.push_back(entry);
	map_entry_index++;
}

void write_data_coe() {
	std::ofstream ofs(file_data_coe, std::ios::out | std::ios::trunc);
	if (!ofs)
		throw std::ios_base::failure("cannot open " + file_data_coe);

	ofs << "memory_initialization_radix = 16;" << std::endl;
	ofs << "memory_initialization_vector = " << std::endl;

	ofs << std::uppercase << std::hex << std::setfill('0');

	for (int i = 0; i < MAX_DATA_BRAM / 16; i++) {
		uint32_t data_0 = 0;
		uint32_t data_1 = 0;
		uint32_t data_2 = 0;
		uint32_t data_3 = 0;
		if (i * 4 < data.size()) {
			data_0 = data[i * 4];
			data_1 = data[i * 4 + 1];
			data_2 = data[i * 4 + 2];
			data_3 = data[i * 4 + 3];
		}
		ofs << std::setw(8) << data_3;
		ofs << std::setw(8) << data_2;
		ofs << std::setw(8) << data_1;
		ofs << std::setw(8) << data_0 << ',';
		ofs << '\n';
	}
	ofs << ";";
	ofs.flush();
}

void write_map_coe() {
	std::ofstream ofs(file_map_coe, std::ios::out | std::ios::trunc);
	if (!ofs)
		throw std::ios_base::failure("cannot open " + file_map_coe);

	ofs << "memory_initialization_radix = 16;" << std::endl;
	ofs << "memory_initialization_vector = " << std::endl;

	ofs << std::uppercase << std::hex << std::setfill('0');

	for (int i = 0; i < sizeof(map_entries) / 12; i++) {
		uint32_t* data_0 = ((uint32_t*)map_entries) + i * 3;
		uint32_t* data_1 = data_0 + 1;
		uint32_t* data_2 = data_0 + 2;

		ofs << std::setw(8) << *data_2;
		ofs << std::setw(8) << *data_1;
		ofs << std::setw(8) << *data_0 << ',';
		ofs << '\n';
	}
	ofs << ";";
	ofs.flush();
}

struct setup_t {
	uint8_t bm_request_type;
	uint8_t b_request;

	uint16_t w_value;
	uint16_t w_index;
	uint16_t w_length;
};

struct usbmon_packet {
	uint64_t id;             /*  0: URB ID - from submission to callback */
	unsigned char type;      /*  8: Same as text; extensible. */
	unsigned char xfer_type; /*     ISO (0), Intr, Control, Bulk (3) */
	unsigned char epnum;     /*     Endpoint number and transfer direction */
	unsigned char devnum;    /*     Device address */
	uint16_t busnum;         /* 12: Bus number */
	char flag_setup;         /* 14: Same as text */
	char flag_data;          /* 15: Same as text; Binary zero is OK. */
	int64_t ts_sec;          /* 16: gettimeofday */
	int32_t ts_usec;         /* 24: gettimeofday */
	int32_t status;          /* 28: */
	unsigned int length;     /* 32: Length of data (submitted or actual) */
	unsigned int len_cap;    /* 36: Delivered length */
	union {                  /* 40: */
		//unsigned char setup[8];         /* Only for Control S-type */
		setup_t setup;
		struct iso_rec {                /* Only for ISO */
			int32_t error_count;
			int32_t numdesc;
		} iso;
	} s;
	int32_t interval;        /* 48: Only for Interrupt and ISO */
	int32_t start_frame;     /* 52: For ISO */
	uint32_t xfer_flags;     /* 56: copy of URB's transfer_flags */
	uint32_t ndesc;          /* 60: Actual number of ISO descriptors */
};

void init_device_map() {
	device_map dev_map = {};
	dev_map.bus_num = 1;
	dev_map.dev_num = 4;
	dev_map.slot_id = 1;
	devices.push_back(dev_map);
}

std::map<uint64_t, usbmon_packet> pending_setups;


void load_pcap() {
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_offline(pcap_capture_file.c_str(), errbuf);

	if (handle == NULL) {
		std::cerr << errbuf << std::endl;
		return;
	}

	pcap_pkthdr* header;
	usbmon_packet* packet;

	int result;
	printf("datalink: %d\n", pcap_datalink(handle));
	while ((result = pcap_next_ex(handle, &header, (const u_char**) &packet)) == 1) {
		device_map *match_dev = 0;
		for (device_map& dev_map : devices)
			if (dev_map.bus_num == packet->busnum && dev_map.dev_num == packet->devnum)
				match_dev = &dev_map;
		if (!match_dev)
			continue;

		//Ctrl Packet + Submit
		if (packet->xfer_type == 2 && packet->type == 'S') {
			printf("SUBMIT  : packet: %llX %d.%d.%d\n", packet->id, packet->busnum, packet->devnum, packet->epnum & 0xF);
			pending_setups[packet->id] = *packet;
		}
		if (packet->xfer_type == 2 && packet->type == 'C') {
			printf("COMPLETE: packet: %llX %d.%d.%d\n", packet->id, packet->busnum, packet->devnum, packet->epnum & 0xF);
			setup_t setup = pending_setups[packet->id].s.setup;
			printf(" %02X %02X %04X %04X %d\n", setup.bm_request_type, setup.b_request, setup.w_index, setup.w_value, setup.w_length);
			void* payload = (void*)((uint64_t)packet + sizeof(*packet));

			void* buffer = 0;
			if (setup.w_length != 0) {
				buffer = malloc(setup.w_length);
				if (!buffer) {
					printf("failed to allocate buffer!\n");
					return;
				}
				memcpy(buffer, payload, setup.w_length);
			}

			new_entry(match_dev->slot_id, packet->epnum & 0xF, setup.bm_request_type, setup.b_request, setup.w_value, setup.w_index, setup.w_length, 0, buffer);
		}
	}
}

void init_bram_data() {
	uint16_t index = 0;

	void* buffer = malloc(0x10);
	uint32_t* data_1 = (uint32_t*)buffer;
	uint32_t* data_2 = data_1 + 1;
	uint32_t* data_3 = data_1 + 2;
	uint32_t* data_4 = data_1 + 3;
	if (!buffer) {
		printf("Failed to allocate buffer!\n");
		return;
	}

	for (usb_packet_entry& entry : entries) {
		if (entry.map_entry->data_length == 0)
			continue;

		uint16_t data_count = entry.map_entry->data_length >> 4;
		uint16_t data_left = entry.map_entry->data_length & 0xF;
		uint16_t data_size = data_count + (data_left != 0 ? 1 : 0);

		//printf("%03d: data length: %d, size: %d\n", index, entry.map_entry->data_length, data_size);
		printf("%03d: size: %02d(%04d) => %02X %02X %04X %04X\n", index, data_size, entry.map_entry->data_length, entry.map_entry->bm_request_type, entry.map_entry->b_request, entry.map_entry->w_value, entry.map_entry->w_index);

		for (uint16_t i = 0; i < data_size; i++) {
			memset(buffer, 0, 0x10);
			size_t copy_length = 0x10;
			if (copy_length > entry.map_entry->data_length - i * 0x10)
				copy_length = entry.map_entry->data_length - i * 0x10;
			memcpy(buffer, (void*)((uint64_t)entry.data + i * 0x10), copy_length);
			data.push_back(*data_1);
			data.push_back(*data_2);
			data.push_back(*data_3);
			data.push_back(*data_4);
		}

		entry.map_entry->bram_address = index;

		index += data_size;
	}
}

int main()
{
	init_device_map();
	//load_entries();
	load_pcap();

	init_bram_data();

	write_data_coe();
	write_map_coe();
}