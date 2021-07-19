int get_raw_socket(const char *device_name);
ssize_t read_raw_packet(int socket_descriptor, char **packet);
