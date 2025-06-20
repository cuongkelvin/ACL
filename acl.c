#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <uci.h>
#include <unistd.h>

#define MAX_ID 255       // Giới hạn 8 bit: 2^8 - 1
#define MAX_PRIORITY 65535 // Giới hạn 16 bit: 2^16 - 1
#define MAX_PORTS 100    // Giới hạn số lượng port tối đa trong list port

// Function prototypes
int calculate_loc(struct uci_context *ctx, struct uci_package *pkg, const char* list_name, 
                  const char* rule_name, const char* direction, const char* port_name);
void delete_list(struct uci_context *ctx, const char* list_name);
void remove_port_from_list(struct uci_context *ctx, const char* list_name, const char* port_name, const char* direction);
int list_exists(struct uci_context *ctx, const char* list_name);

// Hàm kiểm tra tính hợp lệ của protocol và action
int validate_input(const char* protocol, const char* action) {
    if (strcmp(protocol, "all") != 0 && strcmp(protocol, "ipv4") != 0 &&
        strcmp(protocol, "ipv6") != 0 && strcmp(protocol, "arp") != 0) {
        return 0;
    }
    if (strcmp(action, "permit") != 0 && strcmp(action, "deny") != 0) {
        return 0;
    }
    return 1;
}

// Hàm kiểm tra tính hợp lệ của tên
int is_safe_string(const char* str) {
    return str[strspn(str, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-")] == '\0';
}

// Hàm kiểm tra xem rule đã tồn tại chưa
int rule_exists(struct uci_context *ctx, const char* rule_name) {
    struct uci_package *pkg = NULL;
    struct uci_section *s;

    if (!is_safe_string(rule_name)) {
        fprintf(stderr, "Lỗi: Tên rule '%s' chứa ký tự không hợp lệ.\n", rule_name);
        return 1;
    }

    if (uci_load(ctx, "rule_mac", &pkg) != UCI_OK) {
        fprintf(stderr, "Lỗi: Không thể tải package rule_mac trong rule_exists.\n");
        return 0;
    }

    s = uci_lookup_section(ctx, pkg, rule_name);
    int exists = (s != NULL && strcmp(s->type, "rule") == 0);
    uci_unload(ctx, pkg);
    return exists;
}

// Hàm kiểm tra xem listmac đã tồn tại chưa
int list_exists(struct uci_context *ctx, const char* list_name) {
    struct uci_package *pkg = NULL;
    struct uci_section *s;

    if (!is_safe_string(list_name)) {
        fprintf(stderr, "Lỗi: Tên list '%s' chứa ký tự không hợp lệ.\n", list_name);
        return 1;
    }

    if (uci_load(ctx, "rule_mac", &pkg) != UCI_OK) {
        fprintf(stderr, "Lỗi: Không thể tải package rule_mac trong list_exists. Kiểm tra tệp /etc/config/rule_mac.\n");
        return 0;
    }

    s = uci_lookup_section(ctx, pkg, list_name);
    if (s == NULL) {
        uci_unload(ctx, pkg);
        return 0;
    }
    if (strcmp(s->type, "listmac") != 0) {
        fprintf(stderr, "Lỗi: Section '%s' không phải loại listmac.\n", list_name);
        uci_unload(ctx, pkg);
        return 0;
    }

    uci_unload(ctx, pkg);
    return 1;
}

// Hàm kiểm tra xem rule đã có trong listmac chưa
int rule_in_list(struct uci_context *ctx, const char* list_name, const char* rule_name) {
    struct uci_package *pkg = NULL;
    struct uci_section *s = NULL;
    struct uci_option *opt = NULL;
    struct uci_element *e;

    if (!is_safe_string(list_name) || !is_safe_string(rule_name)) {
        fprintf(stderr, "Lỗi: Tên list hoặc rule chứa ký tự không hợp lệ.\n");
        return 0;
    }

    if (uci_load(ctx, "rule_mac", &pkg) != UCI_OK) {
        fprintf(stderr, "Lỗi: Không thể tải package rule_mac trong rule_in_list.\n");
        return 0;
    }

    s = uci_lookup_section(ctx, pkg, list_name);
    if (!s || strcmp(s->type, "listmac") != 0) {
        uci_unload(ctx, pkg);
        return 0;
    }

    opt = uci_lookup_option(ctx, s, "rule");
    if (!opt) {
        uci_unload(ctx, pkg);
        return 0;
    }

    uci_foreach_element(&opt->v.list, e) {
        if (strcmp(e->name, rule_name) == 0) {
            uci_unload(ctx, pkg);
            return 1;
        }
    }

    uci_unload(ctx, pkg);
    return 0;
}

// Hàm kiểm tra xem port đã có trong listmac chưa
int port_in_listmac(struct uci_context *ctx, struct uci_package *pkg, const char* list_name, const char* port_name) {
    struct uci_section *s;
    struct uci_option *opt;
    struct uci_element *e;

    s = uci_lookup_section(ctx, pkg, list_name);
    if (!s || strcmp(s->type, "listmac") != 0) {
        fprintf(stderr, "Lỗi: Listmac '%s' không tồn tại trong port_in_listmac.\n", list_name);
        return 0;
    }

    opt = uci_lookup_option(ctx, s, "port");
    if (!opt) {
        return 0; // Không có danh sách port
    }

    uci_foreach_element(&opt->v.list, e) {
        if (strcmp(e->name, port_name) == 0) {
            return 1; // Port đã tồn tại
        }
    }

    return 0; // Port chưa tồn tại
}

// Hàm kiểm tra xem port đã được cấu hình với list nào chưa cho một direction
const char* port_has_list(struct uci_context *ctx, struct uci_package *pkg, const char* port_name, const char* direction) {
    struct uci_section *s;
    struct uci_option *opt;

    if (!is_safe_string(port_name) || !is_safe_string(direction)) {
        fprintf(stderr, "Lỗi: Tên port hoặc direction chứa ký tự không hợp lệ.\n");
        return NULL;
    }

    s = uci_lookup_section(ctx, pkg, port_name);
    if (!s || strcmp(s->type, "port") != 0) {
        return NULL; // Port không tồn tại hoặc không phải section port
    }

    char config_option[16];
    snprintf(config_option, sizeof(config_option), "config_%s", direction);
    opt = uci_lookup_option(ctx, s, config_option);
    if (!opt || strcmp(opt->v.string, "0") == 0) {
        return NULL; // Direction chưa được cấu hình
    }

    return opt->v.string; // Trả về tên listmac hiện tại
}

// Hàm kiểm tra xem ID đã được sử dụng bởi listmac nào chưa
int id_exists(struct uci_context *ctx, int id) {
    struct uci_package *pkg = NULL;
    struct uci_section *s;
    struct uci_element *e;

    if (id < 1 || id > MAX_ID) return 1; // ID ngoài khoảng [1, 255]

    if (uci_load(ctx, "rule_mac", &pkg) != UCI_OK) {
        fprintf(stderr, "Lỗi: Không thể tải package rule_mac trong id_exists.\n");
        return 0;
    }

    uci_foreach_element(&pkg->sections, e) {
        s = uci_to_section(e);
        if (strcmp(s->type, "listmac") == 0) {
            struct uci_option *opt = uci_lookup_option(ctx, s, "id");
            if (opt && atoi(opt->v.string) == id) {
                uci_unload(ctx, pkg);
                return 1;
            }
        }
    }

    uci_unload(ctx, pkg);
    return 0;
}

// Hàm tìm ID nhỏ nhất chưa sử dụng
int find_available_id(struct uci_context *ctx) {
    for (int id = 1; id <= MAX_ID; id++) {
        if (!id_exists(ctx, id)) {
            return id;
        }
    }
    return -1; // Không còn ID khả dụng
}

// Hàm thêm rule mới
void add_rule(struct uci_context *ctx, const char* rule_name, const char* srcmac, const char* dstmac,
              const char* protocol, const char* action, int priority) {
    struct uci_package *pkg = NULL;
    struct uci_ptr ptr = {0};

    if (!is_safe_string(rule_name)) {
        printf("Lỗi: Tên rule '%s' chứa ký tự không hợp lệ.\n", rule_name);
        return;
    }
    if (rule_exists(ctx, rule_name)) {
        printf("Lỗi: Rule '%s' đã tồn tại.\n", rule_name);
        return;
    }
    if (!validate_input(protocol, action)) {
        printf("Lỗi: Protocol hoặc action không hợp lệ.\n");
        return;
    }
    if (priority < 0 || priority > MAX_PRIORITY) {
        printf("Lỗi: Priority phải nằm trong khoảng [0, %d].\n", MAX_PRIORITY);
        return;
    }

    if (uci_load(ctx, "rule_mac", &pkg) != UCI_OK) {
        fprintf(stderr, "Lỗi: Không thể tải package rule_mac trong add_rule.\n");
        uci_unload(ctx, pkg);
        pkg = NULL;
    }

    ptr.package = "rule_mac";
    ptr.section = rule_name;
    ptr.value = "rule";
    if (uci_set(ctx, &ptr) != UCI_OK) {
        printf("Lỗi: Không thể tạo section rule '%s'.\n", rule_name);
        uci_unload(ctx, pkg);
        return;
    }

    char priority_str[16];
    snprintf(priority_str, sizeof(priority_str), "%d", priority);

    struct { const char* name; const char* value; } options[] = {
        {"srcmac", srcmac},
        {"dstmac", dstmac},
        {"protocol", protocol},
        {"action", action},
        {"priority", priority_str}
    };

    for (int i = 0; i < sizeof(options)/sizeof(options[0]); i++) {
        // Reset ptr struct trước mỗi lần set option
        memset(&ptr, 0, sizeof(ptr));
        ptr.package = "rule_mac";
        ptr.section = rule_name;
        ptr.option = options[i].name;
        ptr.value = options[i].value;
        if (uci_set(ctx, &ptr) != UCI_OK) {
            printf("Lỗi: Không thể đặt %s cho rule '%s'.\n", options[i].name, rule_name);
            uci_unload(ctx, pkg);
            return;
        }
    }

    uci_save(ctx, pkg);
    if (uci_commit(ctx, &pkg, false) != UCI_OK) {
        printf("Lỗi: Không thể commit thay đổi cho rule '%s'.\n", rule_name);
        uci_unload(ctx, pkg);
        return;
    }
    uci_unload(ctx, pkg);
    printf("Thêm rule '%s' thành công.\n", rule_name);
}

// Hàm thêm listmac mới với ID duy nhất và rule mặc định
void add_list(struct uci_context *ctx, const char* list_name, const char* default_rule_type) {
    struct uci_package *pkg = NULL;
    struct uci_ptr ptr = {0};

    if (!is_safe_string(list_name)) {
        printf("Lỗi: Tên list '%s' chứa ký tự không hợp lệ.\n", list_name);
        return;
    }
    if (list_exists(ctx, list_name)) {
        printf("Lỗi: List '%s' đã tồn tại.\n", list_name);
        return;
    }

    const char* rule_to_add;
    if (strcmp(default_rule_type, "blockall") == 0) {
        rule_to_add = "deny_all";
    } else if (strcmp(default_rule_type, "accept_all") == 0) {
        rule_to_add = "permit_all";
    } else {
        printf("Lỗi: Loại rule mặc định '%s' không hợp lệ. Phải là 'blockall' hoặc 'accept_all'.\n", default_rule_type);
        return;
    }

    if (!rule_exists(ctx, rule_to_add)) {
        printf("Lỗi: Rule mặc định '%s' không tồn tại.\n", rule_to_add);
        return;
    }

    int new_id = find_available_id(ctx);
    if (new_id == -1) {
        printf("Lỗi: Không còn ID khả dụng trong khoảng 1 đến %d.\n", MAX_ID);
        return;
    }

    if (uci_load(ctx, "rule_mac", &pkg) != UCI_OK) {
        fprintf(stderr, "Lỗi: Không thể tải package rule_mac trong add_list.\n");
        uci_unload(ctx, pkg);
        pkg = NULL;
    }

    ptr.package = "rule_mac";
    ptr.section = list_name;
    ptr.value = "listmac";
    if (uci_set(ctx, &ptr) != UCI_OK) {
        printf("Lỗi: Không thể tạo section listmac '%s'.\n", list_name);
        uci_unload(ctx, pkg);
        return;
    }

    char id_str[16];
    snprintf(id_str, sizeof(id_str), "%d", new_id);
    ptr.option = "id";
    ptr.value = id_str;
    if (uci_set(ctx, &ptr) != UCI_OK) {
        printf("Lỗi: Không thể đặt id cho listmac '%s'.\n", list_name);
        uci_unload(ctx, pkg);
        return;
    }

    ptr.option = "rule";
    ptr.value = rule_to_add;
    if (uci_add_list(ctx, &ptr) != UCI_OK) {
        printf("Lỗi: Không thể thêm rule mặc định '%s' vào list '%s'.\n", rule_to_add, list_name);
        uci_unload(ctx, pkg);
        return;
    }

    uci_save(ctx, pkg);
    if (uci_commit(ctx, &pkg, false) != UCI_OK) {
        printf("Lỗi: Không thể commit thay đổi cho listmac '%s'.\n", list_name);
        uci_unload(ctx, pkg);
        return;
    }
    uci_unload(ctx, pkg);
    printf("Thêm list '%s' với ID '%d' và rule mặc định '%s' thành công.\n", list_name, new_id, rule_to_add);
}

// Hàm gắn rule vào listmac và áp dụng ethtool nếu có port
void add_rule_to_list(struct uci_context *ctx, const char* rule_name, const char* list_name) {
    struct uci_package *pkg = NULL;
    struct uci_ptr ptr = {0};
    struct uci_section *s;
    struct uci_option *opt;
    struct uci_element *e;
    int success = 1;

    if (!rule_exists(ctx, rule_name)) {
        printf("Lỗi: Rule '%s' không tồn tại.\n", rule_name);
        return;
    }
    if (!list_exists(ctx, list_name)) {
        printf("Lỗi: List '%s' không tồn tại.\n", list_name);
        return;
    }
    if (rule_in_list(ctx, list_name, rule_name)) {
        printf("Lỗi: Rule '%s' đã có trong list '%s'.\n", rule_name, list_name);
        return;
    }

    if (uci_load(ctx, "rule_mac", &pkg) != UCI_OK) {
        fprintf(stderr, "Lỗi: Không thể tải package rule_mac trong add_rule_to_list, mã lỗi UCI: %d\n", ctx->err);
        switch (ctx->err) {
            case UCI_ERR_MEM: fprintf(stderr, "Lỗi: Hết bộ nhớ\n"); break;
            case UCI_ERR_INVAL: fprintf(stderr, "Lỗi: Tên package không hợp lệ\n"); break;
            case UCI_ERR_NOTFOUND: fprintf(stderr, "Lỗi: Không tìm thấy tệp /etc/config/rule_mac\n"); break;
            case UCI_ERR_IO: fprintf(stderr, "Lỗi: Lỗi đọc/ghi tệp\n"); break;
            case UCI_ERR_PARSE: fprintf(stderr, "Lỗi: Lỗi phân tích cú pháp tệp\n"); break;
            default: fprintf(stderr, "Lỗi: Lỗi UCI không xác định\n"); break;
        }
        return;
    }

    // Thêm rule vào listmac
    ptr.package = "rule_mac";
    ptr.section = list_name;
    ptr.option = "rule";
    ptr.value = rule_name;
    if (uci_add_list(ctx, &ptr) != UCI_OK) {
        printf("Lỗi: Không thể thêm rule '%s' vào list '%s'.\n", rule_name, list_name);
        uci_unload(ctx, pkg);
        return;
    }

    // Thêm list_name vào list used_by của rule
    ptr.section = rule_name;
    ptr.option = "used_by";
    ptr.value = list_name;
    if (uci_add_list(ctx, &ptr) != UCI_OK) {
        printf("Lỗi: Không thể thêm list '%s' vào used_by của rule '%s'.\n", list_name, rule_name);
        uci_unload(ctx, pkg);
        return;
    }

    // Kiểm tra xem listmac có port nào không
    s = uci_lookup_section(ctx, pkg, list_name);
    if (!s || strcmp(s->type, "listmac") != 0) {
        fprintf(stderr, "Lỗi: Listmac '%s' không tồn tại trong add_rule_to_list.\n", list_name);
        uci_unload(ctx, pkg);
        return;
    }

    opt = uci_lookup_option(ctx, s, "port");
    if (opt) {
        // Có port, áp dụng ethtool
        uci_foreach_element(&opt->v.list, e) {
            const char* full_port_name = e->name;
            // Tách port_name và direction từ full_port_name (e.g., eth1_in -> eth1, in)
            char port_name[256];
            char direction[8];
            if (sscanf(full_port_name, "%255[^_]_%7s", port_name, direction) != 2) {
                fprintf(stderr, "Lỗi: Port '%s' không đúng định dạng (phải là <port>_<in/out>).\n", full_port_name);
                success = 0;
                continue;
            }
            if (strcmp(direction, "in") != 0 && strcmp(direction, "out") != 0) {
                fprintf(stderr, "Lỗi: Direction '%s' không hợp lệ cho port '%s'.\n", direction, port_name);
                success = 0;
                continue;
            }
            // Gọi calculate_loc để chạy ethtool
            if (calculate_loc(ctx, pkg, list_name, rule_name, direction, port_name) != 0) {
                fprintf(stderr, "Lỗi: Không thể áp dụng ethtool cho rule '%s' trên port '%s_%s'.\n", rule_name, port_name, direction);
                success = 0;
                break;
            }
        }
    }

    if (!success) {
        fprintf(stderr, "Lỗi: Không thể áp dụng tất cả quy tắc ethtool, hủy bỏ thay đổi UCI.\n");
        uci_unload(ctx, pkg);
        return;
    }

    uci_save(ctx, pkg);
    if (uci_commit(ctx, &pkg, false) != UCI_OK) {
        printf("Lỗi: Không thể commit thay đổi cho listmac '%s'.\n", list_name);
        uci_unload(ctx, pkg);
        return;
    }
    uci_unload(ctx, pkg);
    printf("Thêm rule '%s' vào list '%s'%s thành công.\n", rule_name, list_name, opt ? " và áp dụng ethtool" : "");
}

// Hàm tính giá trị loc 32-bit và chạy lệnh ethtool
int calculate_loc(struct uci_context *ctx, struct uci_package *pkg, const char* list_name, 
                  const char* rule_name, const char* direction, const char* port_name) {
    struct uci_section *s;
    struct uci_option *opt;
    uint32_t loc = 0;

    s = uci_lookup_section(ctx, pkg, list_name);
    if (!s || strcmp(s->type, "listmac") != 0) {
        fprintf(stderr, "Lỗi: Listmac '%s' không tồn tại trong calculate_loc.\n", list_name);
        return -1;
    }

    opt = uci_lookup_option(ctx, s, "id");
    if (!opt) {
        fprintf(stderr, "Lỗi: Không tìm thấy id cho listmac '%s' trong calculate_loc.\n", list_name);
        return -1;
    }
    uint32_t acl_id = atoi(opt->v.string);

    s = uci_lookup_section(ctx, pkg, rule_name);
    if (!s || strcmp(s->type, "rule") != 0) {
        fprintf(stderr, "Lỗi: Rule '%s' không tồn tại trong calculate_loc.\n", rule_name);
        return -1;
    }

    opt = uci_lookup_option(ctx, s, "priority");
    if (!opt) {
        fprintf(stderr, "Lỗi: Không tìm thấy priority cho rule '%s' trong calculate_loc.\n", rule_name);
        return -1;
    }
    uint32_t priority = atoi(opt->v.string);

    opt = uci_lookup_option(ctx, s, "srcmac");
    if (!opt) {
        fprintf(stderr, "Lỗi: Không tìm thấy srcmac cho rule '%s' trong calculate_loc.\n", rule_name);
        return -1;
    }
    const char* srcmac = opt->v.string;

    opt = uci_lookup_option(ctx, s, "dstmac");
    if (!opt) {
        fprintf(stderr, "Lỗi: Không tìm thấy dstmac cho rule '%s' trong calculate_loc.\n", rule_name);
        return -1;
    }
    const char* dstmac = opt->v.string;

    opt = uci_lookup_option(ctx, s, "protocol");
    if (!opt) {
        fprintf(stderr, "Lỗi: Không tìm thấy protocol cho rule '%s' trong calculate_loc.\n", rule_name);
        return -1;
    }
    const char* protocol = opt->v.string;

    opt = uci_lookup_option(ctx, s, "action");
    if (!opt) {
        fprintf(stderr, "Lỗi: Không tìm thấy action cho rule '%s' trong calculate_loc.\n", rule_name);
        return -1;
    }
    const char* action = opt->v.string;

    uint32_t dir_bit = (strcmp(direction, "in") == 0) ? 0 : 1;
    loc = (dir_bit << 24) | (acl_id << 16) | (priority & 0xFFFF);

    char proto_str[16];
    if (strcmp(protocol, "all") == 0) {
        snprintf(proto_str, sizeof(proto_str), "0");
    } else if (strcmp(protocol, "ipv4") == 0) {
        snprintf(proto_str, sizeof(proto_str), "0x0800");
    } else if (strcmp(protocol, "ipv6") == 0) {
        snprintf(proto_str, sizeof(proto_str), "0x86DD");
    } else if (strcmp(protocol, "arp") == 0) {
        snprintf(proto_str, sizeof(proto_str), "0x0806");
    } else {
        fprintf(stderr, "Lỗi: Protocol '%s' không hợp lệ cho rule '%s'.\n", protocol, rule_name);
        return -1;
    }
    printf("action: %s\n", action);
    // Map action đúng: permit = 1, deny = 0
    int ethtool_action;
    if (strcmp(action, "permit") == 0) {
        ethtool_action = 1;  // permit = action 1 (allow traffic)
    } else if (strcmp(action, "deny") == 0) {
        ethtool_action = 0;  // deny = action 0 (drop traffic)
    } else {
        fprintf(stderr, "Lỗi: Action '%s' không hợp lệ cho rule '%s'.\n", action, rule_name);
        return -1;
    }

    printf("Rule: %s, loc: 0x%08X, action: %s -> %d\n", rule_name, loc, action, ethtool_action);

    char command[512];
    snprintf(command, sizeof(command),
             "ethtool -N %s flow-type ether src %s dst %s action %d loc %u proto %s",
             port_name, srcmac, dstmac, ethtool_action, loc, proto_str);

    printf("Thực thi lệnh: %s\n", command);
    sleep(1);
    int ret = system(command);
    if (ret != 0) {
        fprintf(stderr, "Lỗi: Thực thi lệnh ethtool cho rule '%s' thất bại (mã lỗi: %d).\n", rule_name, ret);
        return -1;
    }

    return 0;
}

// Hàm xóa rule khỏi listmac và áp dụng ethtool delete nếu có port
void delete_rule_from_list(struct uci_context *ctx, const char* rule_name, const char* list_name) {
    struct uci_package *pkg = NULL;
    struct uci_ptr ptr = {0};
    struct uci_section *s;
    struct uci_option *opt;
    struct uci_element *e;
    int success = 1;

    if (!ctx || !rule_name || !list_name) {
        fprintf(stderr, "Lỗi: Tham số đầu vào không hợp lệ.\n");
        return;
    }

    if (!rule_exists(ctx, rule_name)) {
        fprintf(stderr, "Lỗi: Rule '%s' không tồn tại.\n", rule_name);
        return;
    }
    if (!list_exists(ctx, list_name)) {
        fprintf(stderr, "Lỗi: List '%s' không tồn tại.\n", list_name);
        return;
    }
    if (!rule_in_list(ctx, list_name, rule_name)) {
        fprintf(stderr, "Lỗi: Rule '%s' không có trong list '%s'.\n", rule_name, list_name);
        return;
    }

    if (uci_load(ctx, "rule_mac", &pkg) != UCI_OK) {
        fprintf(stderr, "Lỗi: Không thể tải package rule_mac (UCI error: %d).\n", ctx->err);
        return;
    }

    // Xóa rule trên các port bằng ethtool TRƯỚC KHI xóa khỏi UCI
    s = uci_lookup_section(ctx, pkg, list_name);
    if (!s || strcmp(s->type, "listmac") != 0) {
        fprintf(stderr, "Lỗi: Listmac '%s' không tồn tại.\n", list_name);
        uci_unload(ctx, pkg);
        return;
    }

    opt = uci_lookup_option(ctx, s, "port");
    if (opt) {
        uci_foreach_element(&opt->v.list, e) {
            const char* full_port_name = e->name;
            char port_name[256] = {0};
            char direction[8] = {0};
            if (sscanf(full_port_name, "%255[^_]_%7s", port_name, direction) != 2) {
                fprintf(stderr, "Lỗi: Port '%s' không đúng định dạng.\n", full_port_name);
                success = 0;
                continue;
            }
            if (strcmp(direction, "in") != 0 && strcmp(direction, "out") != 0) {
                fprintf(stderr, "Lỗi: Direction '%s' không hợp lệ cho port '%s'.\n", direction, port_name);
                success = 0;
                continue;
            }

            struct uci_section *rule_s = uci_lookup_section(ctx, pkg, rule_name);
            if (!rule_s || strcmp(rule_s->type, "rule") != 0) {
                fprintf(stderr, "Lỗi: Rule '%s' không tồn tại.\n", rule_name);
                success = 0;
                continue;
            }

            struct uci_option *id_opt = uci_lookup_option(ctx, s, "id");
            if (!id_opt) {
                fprintf(stderr, "Lỗi: Không tìm thấy id cho listmac '%s'.\n", list_name);
                success = 0;
                continue;
            }
            uint32_t acl_id = atoi(id_opt->v.string);

            struct uci_option *priority_opt = uci_lookup_option(ctx, rule_s, "priority");
            if (!priority_opt) {
                fprintf(stderr, "Lỗi: Không tìm thấy priority cho rule '%s'.\n", rule_name);
                success = 0;
                continue;
            }
            uint32_t priority = atoi(priority_opt->v.string);

            uint32_t dir_bit = (strcmp(direction, "in") == 0) ? 0 : 1;
            uint32_t loc = (dir_bit << 24) | (acl_id << 16) | (priority & 0xFFFF);

            char command[512];
            snprintf(command, sizeof(command), "ethtool -N %s delete %u", port_name, loc);
            printf("Debug: Thực thi lệnh: %s\n", command);
            sleep(1);
            int ret = system(command);
            if (ret != 0) {
                fprintf(stderr, "Cảnh báo: Thực thi ethtool delete cho rule '%s' thất bại (mã lỗi: %d).\n", 
                        rule_name, ret);
                // Không dừng lại, tiếp tục xóa các rule khác
            }
        }
    }

    if (!success) {
        fprintf(stderr, "Lỗi: Không thể thực thi tất cả lệnh ethtool delete.\n");
        uci_unload(ctx, pkg);
        return;
    }

    // Reset ptr struct before each use
    memset(&ptr, 0, sizeof(ptr));
    ptr.package = "rule_mac";
    ptr.section = list_name;
    ptr.option = "rule";
    ptr.value = rule_name;
    if (uci_del_list(ctx, &ptr) != UCI_OK) {
        fprintf(stderr, "Lỗi: Không thể xóa rule '%s' khỏi list '%s' (UCI error: %d).\n", rule_name, list_name, ctx->err);
        uci_unload(ctx, pkg);
        return;
    }
    printf("Debug: Xóa rule '%s' khỏi list '%s' thành công.\n", rule_name, list_name);

    // Reset ptr struct before each use
    memset(&ptr, 0, sizeof(ptr));
    ptr.package = "rule_mac";
    ptr.section = rule_name;
    ptr.option = "used_by";
    ptr.value = list_name;
    if (uci_del_list(ctx, &ptr) != UCI_OK) {
        fprintf(stderr, "Lỗi: Không thể xóa list '%s' khỏi used_by của rule '%s' (UCI error: %d).\n", list_name, rule_name, ctx->err);
        uci_unload(ctx, pkg);
        return;
    }
    printf("Debug: Xóa list '%s' khỏi used_by của rule '%s' thành công.\n", list_name, rule_name);

    // Lưu và commit thay đổi sau khi xóa rule
    if (uci_save(ctx, pkg) != UCI_OK || uci_commit(ctx, &pkg, false) != UCI_OK) {
        fprintf(stderr, "Lỗi: Không thể commit thay đổi khi xóa rule '%s' (UCI error: %d).\n", rule_name, ctx->err);
        uci_unload(ctx, pkg);
        return;
    }
    printf("Debug: Commit thay đổi sau khi xóa rule thành công.\n");

    // Reload package để đảm bảo trạng thái UCI nhất quán
    uci_unload(ctx, pkg);
    if (uci_load(ctx, "rule_mac", &pkg) != UCI_OK) {
        fprintf(stderr, "Lỗi: Không thể reload package rule_mac (UCI error: %d).\n", ctx->err);
        return;
    }

    // Kiểm tra listmac
    s = uci_lookup_section(ctx, pkg, list_name);
    if (!s || strcmp(s->type, "listmac") != 0) {
        fprintf(stderr, "Lỗi: Listmac '%s' không tồn tại.\n", list_name);
        uci_unload(ctx, pkg);
        return;
    }

    // Kiểm tra danh sách rule có rỗng không
    opt = uci_lookup_option(ctx, s, "rule");
    if (!opt || uci_list_empty(&opt->v.list)) {
        printf("Debug: Danh sách rule của listmac '%s' rỗng.\n", list_name);

        // Xóa tất cả port và cập nhật config
        opt = uci_lookup_option(ctx, s, "port");
        if (opt && !uci_list_empty(&opt->v.list)) {
            // Tạo array để lưu tên port và direction
            struct port_info {
                char port_name[256];
                char direction[8];
                char full_name[264];
            };
            
            struct port_info ports[MAX_PORTS];
            int port_count = 0;

            // Lưu thông tin port vào array
            uci_foreach_element(&opt->v.list, e) {
                if (port_count >= MAX_PORTS) {
                    fprintf(stderr, "Lỗi: Quá nhiều port trong listmac '%s' (giới hạn %d).\n", list_name, MAX_PORTS);
                    break;
                }
                
                strncpy(ports[port_count].full_name, e->name, sizeof(ports[port_count].full_name) - 1);
                ports[port_count].full_name[sizeof(ports[port_count].full_name) - 1] = '\0';
                
                if (sscanf(e->name, "%255[^_]_%7s", ports[port_count].port_name, ports[port_count].direction) != 2) {
                    fprintf(stderr, "Lỗi: Port '%s' không đúng định dạng.\n", e->name);
                    continue;
                }
                
                if (strcmp(ports[port_count].direction, "in") != 0 && strcmp(ports[port_count].direction, "out") != 0) {
                    fprintf(stderr, "Lỗi: Direction '%s' không hợp lệ.\n", ports[port_count].direction);
                    continue;
                }

                port_count++;
            }

            // Xử lý từng port
            for (int i = 0; i < port_count; i++) {
                printf("Debug: Bắt đầu xử lý port '%s'.\n", ports[i].full_name);

                // Xóa port khỏi list port của listmac
                memset(&ptr, 0, sizeof(ptr));
                ptr.package = "rule_mac";
                ptr.section = list_name;
                ptr.option = "port";
                ptr.value = ports[i].full_name;
                if (uci_del_list(ctx, &ptr) != UCI_OK) {
                    fprintf(stderr, "Lỗi: Không thể xóa port '%s' khỏi list '%s' (UCI error: %d).\n", 
                            ports[i].full_name, list_name, ctx->err);
                    success = 0;
                    continue;
                }
                printf("Debug: Xóa port '%s' khỏi list '%s' thành công.\n", ports[i].full_name, list_name);

                // Cập nhật config_in hoặc config_out
                struct uci_section *port_s = uci_lookup_section(ctx, pkg, ports[i].port_name);
                if (!port_s || !port_s->type || strcmp(port_s->type, "port") != 0) {
                    fprintf(stderr, "Lỗi: Port section '%s' không tồn tại hoặc không phải section port.\n", ports[i].port_name);
                    success = 0;
                    continue;
                }

                char config_option[16];
                snprintf(config_option, sizeof(config_option), "config_%s", ports[i].direction);
                
                printf("Debug: Chuẩn bị đặt %s='0' cho port '%s'.\n", config_option, ports[i].port_name);
                
                memset(&ptr, 0, sizeof(ptr));
                ptr.package = "rule_mac";
                ptr.section = ports[i].port_name;
                ptr.option = config_option;
                ptr.value = "0";
                
                if (uci_set(ctx, &ptr) != UCI_OK) {
                    fprintf(stderr, "Lỗi: Không thể đặt %s='0' cho port '%s' (UCI error: %d).\n", 
                            config_option, ports[i].port_name, ctx->err);
                    success = 0;
                    continue;
                }
                printf("Debug: Đặt %s='0' cho port '%s' thành công.\n", config_option, ports[i].port_name);
            }
        }
    } else {
        printf("Debug: Danh sách rule của listmac '%s' không rỗng.\n", list_name);
    }

    // Lưu và commit thay đổi cuối cùng
    if (success) {
        if (uci_save(ctx, pkg) != UCI_OK || uci_commit(ctx, &pkg, false) != UCI_OK) {
            fprintf(stderr, "Lỗi: Không thể commit thay đổi cuối cùng (UCI error: %d).\n", ctx->err);
            success = 0;
        } else {
            printf("Debug: Commit thay đổi cuối cùng thành công.\n");
        }
    }

    uci_unload(ctx, pkg);
    if (!success) {
        fprintf(stderr, "Lỗi: Có lỗi xảy ra khi xóa rule hoặc port.\n");
        return;
    }

    // Kiểm tra lại xem có port nào đã được xử lý không
    int has_processed_ports = 0;
    if (uci_load(ctx, "rule_mac", &pkg) == UCI_OK) {
        s = uci_lookup_section(ctx, pkg, list_name);
        if (s && strcmp(s->type, "listmac") == 0) {
            opt = uci_lookup_option(ctx, s, "rule");
            if (!opt || uci_list_empty(&opt->v.list)) {
                has_processed_ports = 1;
            }
        }
        uci_unload(ctx, pkg);
    }

    printf("Xóa rule '%s' khỏi list '%s'%s thành công.\n", rule_name, list_name, 
           has_processed_ports ? " và các port liên quan" : "");
    
    // Kiểm tra xem listmac có còn rule nào không sau khi xóa
    if (uci_load(ctx, "rule_mac", &pkg) == UCI_OK) {
        s = uci_lookup_section(ctx, pkg, list_name);
        if (s && strcmp(s->type, "listmac") == 0) {
            opt = uci_lookup_option(ctx, s, "rule");
            if (!opt || uci_list_empty(&opt->v.list)) {
                // Listmac trống, tự động dọn dẹp và xóa list
                printf("Listmac '%s' đã trống sau khi xóa rule, tự động dọn dẹp...\n", list_name);
                
                // Lưu danh sách các port cần dọn dẹp
                char port_names[MAX_PORTS][264]; // Lưu full port name
                int port_count = 0;
                
                struct uci_option *port_opt = uci_lookup_option(ctx, s, "port");
                if (port_opt && !uci_list_empty(&port_opt->v.list)) {
                    struct uci_element *port_e;
                    uci_foreach_element(&port_opt->v.list, port_e) {
                        if (port_count < MAX_PORTS) {
                            strncpy(port_names[port_count], port_e->name, sizeof(port_names[port_count]) - 1);
                            port_names[port_count][sizeof(port_names[port_count]) - 1] = '\0';
                            port_count++;
                        }
                    }
                }
                
                uci_unload(ctx, pkg);
                
                // Dọn dẹp từng port
                for (int i = 0; i < port_count; i++) {
                    char port_name[256];
                    char direction[8];
                    
                    // Parse port_name_direction
                    char *underscore = strrchr(port_names[i], '_');
                    if (underscore && (strcmp(underscore + 1, "in") == 0 || strcmp(underscore + 1, "out") == 0)) {
                        strcpy(direction, underscore + 1);
                        *underscore = '\0';
                        strcpy(port_name, port_names[i]);
                        
                        printf("Dọn dẹp port '%s' direction '%s'...\n", port_name, direction);
                        remove_port_from_list(ctx, list_name, port_name, direction);
                    }
                }
                
                // Xóa listmac
                printf("Xóa listmac trống '%s'...\n", list_name);
                delete_list(ctx, list_name);
                printf("Đã tự động xóa listmac trống '%s' và dọn dẹp tất cả port.\n", list_name);
            } else {
                uci_unload(ctx, pkg);
            }
        } else {
            uci_unload(ctx, pkg);
        }
    }
}

// Hàm gắn list vào port với direction (in/out)
void add_list_to_port(struct uci_context *ctx, const char* list_name, const char* port_name, const char* direction) {
    struct uci_package *pkg = NULL;
    struct uci_ptr ptr = {0};
    struct uci_section *s;
    struct uci_option *opt;
    struct uci_element *e;
    int success = 1;

    if (!list_exists(ctx, list_name)) {
        printf("Lỗi: List '%s' không tồn tại.\n", list_name);
        return;
    }
    if (strcmp(direction, "in") != 0 && strcmp(direction, "out") != 0) {
        printf("Lỗi: Direction phải là 'in' hoặc 'out'.\n");
        return;
    }

    if (uci_load(ctx, "rule_mac", &pkg) != UCI_OK) {
        fprintf(stderr, "Lỗi: Không thể tải package rule_mac trong add_list_to_port, mã lỗi UCI: %d\n", ctx->err);
        switch (ctx->err) {
            case UCI_ERR_MEM: fprintf(stderr, "Lỗi: Hết bộ nhớ\n"); break;
            case UCI_ERR_INVAL: fprintf(stderr, "Lỗi: Tên package không hợp lệ\n"); break;
            case UCI_ERR_NOTFOUND: fprintf(stderr, "Lỗi: Không tìm thấy tệp /etc/config/rule_mac\n"); break;
            case UCI_ERR_IO: fprintf(stderr, "Lỗi: Lỗi đọc/ghi tệp\n"); break;
            case UCI_ERR_PARSE: fprintf(stderr, "Lỗi: Lỗi phân tích cú pháp tệp\n"); break;
            default: fprintf(stderr, "Lỗi: Lỗi UCI không xác định\n"); break;
        }
        return;
    }

    char config_option[16];
    snprintf(config_option, sizeof(config_option), "config_%s", direction);
    char full_port_name[256];
    snprintf(full_port_name, sizeof(full_port_name), "%s_%s", port_name, direction);

    // Kiểm tra xem port đã được cấu hình cho direction này chưa
    const char* existing_list = port_has_list(ctx, pkg, port_name, direction);
    if (existing_list) {
        printf("Lỗi: Port '%s' với direction '%s' đã được gắn với list '%s'.\n", port_name, direction, existing_list);
        uci_unload(ctx, pkg);
        return;
    }

    // Kiểm tra xem full_port_name đã có trong listmac chưa
    if (port_in_listmac(ctx, pkg, list_name, full_port_name)) {
        printf("Lỗi: Port '%s_%s' đã có trong list '%s'.\n", port_name, direction, list_name);
        uci_unload(ctx, pkg);
        return;
    }

    // Áp dụng ethtool cho tất cả rule trong listmac
    s = uci_lookup_section(ctx, pkg, list_name);
    if (!s || strcmp(s->type, "listmac") != 0) {
        fprintf(stderr, "Lỗi: Listmac '%s' không tồn tại trong add_list_to_port.\n", list_name);
        uci_unload(ctx, pkg);
        return;
    }

    opt = uci_lookup_option(ctx, s, "rule");
    if (opt) {
        uci_foreach_element(&opt->v.list, e) {
            if (calculate_loc(ctx, pkg, list_name, e->name, direction, port_name) != 0) {
                fprintf(stderr, "Lỗi: Không thể áp dụng ethtool cho rule '%s' trên port '%s_%s'.\n", e->name, port_name, direction);
                success = 0;
                break;
            }
        }
    } else {
        fprintf(stderr, "Lỗi: Không tìm thấy option 'rule' trong listmac '%s'.\n", list_name);
        uci_unload(ctx, pkg);
        return;
    }

    if (!success) {
        fprintf(stderr, "Lỗi: Không thể áp dụng tất cả quy tắc ethtool, hủy bỏ thay đổi UCI.\n");
        uci_unload(ctx, pkg);
        return;
    }

    // Tạo hoặc cập nhật section port
    ptr.package = "rule_mac";
    ptr.section = port_name;
    ptr.value = "port";
    if (uci_set(ctx, &ptr) != UCI_OK) {
        printf("Lỗi: Không thể tạo section port '%s'.\n", port_name);
        uci_unload(ctx, pkg);
        return;
    }

    // Đặt config_in hoặc config_out
    ptr.option = config_option;
    ptr.value = list_name;
    if (uci_set(ctx, &ptr) != UCI_OK) {
        printf("Lỗi: Không thể đặt %s cho port '%s'.\n", config_option, port_name);
        uci_unload(ctx, pkg);
        return;
    }

    // Thêm full_port_name vào list port của listmac
    ptr.section = list_name;
    ptr.option = "port";
    ptr.value = full_port_name;
    if (uci_add_list(ctx, &ptr) != UCI_OK) {
        printf("Lỗi: Không thể thêm port '%s' vào list '%s'.\n", full_port_name, list_name);
        uci_unload(ctx, pkg);
        return;
    }

    uci_save(ctx, pkg);
    if (uci_commit(ctx, &pkg, false) != UCI_OK) {
        printf("Lỗi: Không thể commit thay đổi cho port '%s'.\n", port_name);
        uci_unload(ctx, pkg);
        return;
    }
    uci_unload(ctx, pkg);
    printf("Thêm list '%s' vào port '%s' với direction '%s' thành công.\n", list_name, port_name, direction);
}

// Hàm xóa rule nếu không được sử dụng
void delete_rule(struct uci_context *ctx, const char* rule_name) {
    struct uci_package *pkg = NULL;
    struct uci_section *s;
    struct uci_option *opt;
    struct uci_element *e;
    char used_by_list[512] = {0};

    if (!is_safe_string(rule_name)) {
        printf("Lỗi: Tên rule '%s' chứa ký tự không hợp lệ.\n", rule_name);
        return;
    }
    if (!rule_exists(ctx, rule_name)) {
        printf("Lỗi: Rule '%s' không tồn tại.\n", rule_name);
        return;
    }

    if (uci_load(ctx, "rule_mac", &pkg) != UCI_OK) {
        fprintf(stderr, "Lỗi: Không thể tải package rule_mac trong delete_rule, mã lỗi UCI: %d\n", ctx->err);
        switch (ctx->err) {
            case UCI_ERR_MEM: fprintf(stderr, "Lỗi: Hết bộ nhớ\n"); break;
            case UCI_ERR_INVAL: fprintf(stderr, "Lỗi: Tên package không hợp lệ\n"); break;
            case UCI_ERR_NOTFOUND: fprintf(stderr, "Lỗi: Không tìm thấy tệp /etc/config/rule_mac\n"); break;
            case UCI_ERR_IO: fprintf(stderr, "Lỗi: Lỗi đọc/ghi tệp\n"); break;
            case UCI_ERR_PARSE: fprintf(stderr, "Lỗi: Lỗi phân tích cú pháp tệp\n"); break;
            default: fprintf(stderr, "Lỗi: Lỗi UCI không xác định\n"); break;
        }
        return;
    }

    s = uci_lookup_section(ctx, pkg, rule_name);
    if (!s || strcmp(s->type, "rule") != 0) {
        printf("Lỗi: Section '%s' không phải loại rule.\n", rule_name);
        uci_unload(ctx, pkg);
        return;
    }

    // Kiểm tra used_by
    opt = uci_lookup_option(ctx, s, "used_by");
    if (opt) {
        uci_foreach_element(&opt->v.list, e) {
            if (strlen(used_by_list) > 0) {
                strncat(used_by_list, ", ", sizeof(used_by_list) - strlen(used_by_list) - 1);
            }
            strncat(used_by_list, e->name, sizeof(used_by_list) - strlen(used_by_list) - 1);
        }
        if (strlen(used_by_list) > 0) {
            printf("Lỗi: Rule '%s' đang được sử dụng bởi list: %s.\n", rule_name, used_by_list);
            uci_unload(ctx, pkg);
            return;
        }
    }

    // Xóa rule
    struct uci_ptr ptr = {0};
    ptr.package = "rule_mac";
    ptr.section = rule_name;
    if (uci_delete(ctx, &ptr) != UCI_OK) {
        printf("Lỗi: Không thể xóa rule '%s'.\n", rule_name);
        uci_unload(ctx, pkg);
        return;
    }

    uci_save(ctx, pkg);
    if (uci_commit(ctx, &pkg, false) != UCI_OK) {
        printf("Lỗi: Không thể commit thay đổi khi xóa rule '%s'.\n", rule_name);
        uci_unload(ctx, pkg);
        return;
    }
    uci_unload(ctx, pkg);
    printf("Xóa rule '%s' thành công.\n", rule_name);
}

// Hàm xóa listmac và giải phóng ID
void delete_list(struct uci_context *ctx, const char* list_name) {
    struct uci_package *pkg = NULL;
    struct uci_section *s;
    struct uci_element *e;

    if (!is_safe_string(list_name)) {
        printf("Lỗi: Tên list '%s' chứa ký tự không hợp lệ.\n", list_name);
        return;
    }
    if (!list_exists(ctx, list_name)) {
        printf("Lỗi: List '%s' không tồn tại.\n", list_name);
        return;
    }

    if (uci_load(ctx, "rule_mac", &pkg) == UCI_OK) {
        uci_foreach_element(&pkg->sections, e) {
            s = uci_to_section(e);
            if (strcmp(s->type, "port") == 0) {
                struct uci_option *opt_in = uci_lookup_option(ctx, s, "config_in");
                struct uci_option *opt_out = uci_lookup_option(ctx, s, "config_out");
                if ((opt_in && strcmp(opt_in->v.string, "0") != 0 && strcmp(opt_in->v.string, list_name) == 0) ||
                    (opt_out && strcmp(opt_out->v.string, "0") != 0 && strcmp(opt_out->v.string, list_name) == 0)) {
                    printf("Lỗi: List '%s' đang được sử dụng bởi port '%s'. Hãy xóa các port liên quan trước.\n", list_name, s->e.name);
                    uci_unload(ctx, pkg);
                    return;
                }
            }
        }
    } else {
        fprintf(stderr, "Lỗi: Không thể tải package rule_mac trong delete_list.\n");
        return;
    }

    struct uci_ptr ptr = {0};
    ptr.package = "rule_mac";
    ptr.section = list_name;
    if (uci_delete(ctx, &ptr) != UCI_OK) {
        printf("Lỗi: Không thể xóa listmac '%s'.\n", list_name);
        uci_unload(ctx, pkg);
        return;
    }

    uci_save(ctx, pkg);
    if (uci_commit(ctx, &pkg, false) != UCI_OK) {
        printf("Lỗi: Không thể commit thay đổi khi xóa listmac '%s'.\n", list_name);
        uci_unload(ctx, pkg);
        return;
    }
    uci_unload(ctx, pkg);
    printf("Xóa list '%s' thành công. ID của nó giờ có thể tái sử dụng.\n", list_name);
}

// Hàm xóa port khỏi listmac và xóa tất cả rule ethtool trên port đó
void remove_port_from_list(struct uci_context *ctx, const char* list_name, const char* port_name, const char* direction) {
    struct uci_package *pkg = NULL;
    struct uci_ptr ptr = {0};
    struct uci_section *s;
    struct uci_option *opt;
    struct uci_element *e;
    int success = 1;
    char full_port_name[256];
    char config_option[16];

    if (!is_safe_string(list_name) || !is_safe_string(port_name) || !is_safe_string(direction)) {
        printf("Lỗi: Tham số chứa ký tự không hợp lệ.\n");
        return;
    }

    if (!list_exists(ctx, list_name)) {
        printf("Lỗi: List '%s' không tồn tại.\n", list_name);
        return;
    }

    if (strcmp(direction, "in") != 0 && strcmp(direction, "out") != 0) {
        printf("Lỗi: Direction phải là 'in' hoặc 'out'.\n");
        return;
    }

    snprintf(full_port_name, sizeof(full_port_name), "%s_%s", port_name, direction);
    snprintf(config_option, sizeof(config_option), "config_%s", direction);

    if (uci_load(ctx, "rule_mac", &pkg) != UCI_OK) {
        fprintf(stderr, "Lỗi: Không thể tải package rule_mac trong remove_port_from_list.\n");
        return;
    }

    // Kiểm tra xem port có trong listmac không
    if (!port_in_listmac(ctx, pkg, list_name, full_port_name)) {
        printf("Lỗi: Port '%s_%s' không có trong list '%s'.\n", port_name, direction, list_name);
        uci_unload(ctx, pkg);
        return;
    }

    // Lấy thông tin listmac
    s = uci_lookup_section(ctx, pkg, list_name);
    if (!s || strcmp(s->type, "listmac") != 0) {
        fprintf(stderr, "Lỗi: Listmac '%s' không tồn tại.\n", list_name);
        uci_unload(ctx, pkg);
        return;
    }

    // Lấy ID của listmac
    struct uci_option *id_opt = uci_lookup_option(ctx, s, "id");
    if (!id_opt) {
        fprintf(stderr, "Lỗi: Không tìm thấy id cho listmac '%s'.\n", list_name);
        uci_unload(ctx, pkg);
        return;
    }
    uint32_t acl_id = atoi(id_opt->v.string);

    // Lấy danh sách rule trong listmac
    opt = uci_lookup_option(ctx, s, "rule");
    if (opt && !uci_list_empty(&opt->v.list)) {
        printf("Đang xóa ethtool rule cho port '%s_%s' trong list '%s'...\n", port_name, direction, list_name);
        
        // Xóa từng rule trên port bằng ethtool
        uci_foreach_element(&opt->v.list, e) {
            const char* rule_name = e->name;
            
            // Lấy thông tin rule
            struct uci_section *rule_s = uci_lookup_section(ctx, pkg, rule_name);
            if (!rule_s || strcmp(rule_s->type, "rule") != 0) {
                fprintf(stderr, "Cảnh báo: Rule '%s' không tồn tại, bỏ qua.\n", rule_name);
                continue;
            }

            struct uci_option *priority_opt = uci_lookup_option(ctx, rule_s, "priority");
            if (!priority_opt) {
                fprintf(stderr, "Cảnh báo: Không tìm thấy priority cho rule '%s', bỏ qua.\n", rule_name);
                continue;
            }
            uint32_t priority = atoi(priority_opt->v.string);

            // Tính loc
            uint32_t dir_bit = (strcmp(direction, "in") == 0) ? 0 : 1;
            uint32_t loc = (dir_bit << 24) | (acl_id << 16) | (priority & 0xFFFF);

            // Chạy lệnh ethtool delete
            char command[512];
            snprintf(command, sizeof(command), "ethtool -N %s delete %u", port_name, loc);
            printf("Thực thi lệnh: %s\n", command);
            sleep(1);
            int ret = system(command);
            if (ret != 0) {
                fprintf(stderr, "Cảnh báo: Thực thi ethtool delete cho rule '%s' thất bại (mã lỗi: %d).\n", rule_name, ret);
                // Không dừng lại, tiếp tục xóa các rule khác
            }
        }
    } else {
        printf("List '%s' không có rule nào.\n", list_name);
    }

    // Xóa port khỏi danh sách port của listmac
    memset(&ptr, 0, sizeof(ptr));
    ptr.package = "rule_mac";
    ptr.section = list_name;
    ptr.option = "port";
    ptr.value = full_port_name;
    if (uci_del_list(ctx, &ptr) != UCI_OK) {
        fprintf(stderr, "Lỗi: Không thể xóa port '%s' khỏi list '%s' (UCI error: %d).\n", full_port_name, list_name, ctx->err);
        success = 0;
    } else {
        printf("Xóa port '%s' khỏi list '%s' thành công.\n", full_port_name, list_name);
    }

    // Cập nhật config_in hoặc config_out của port về '0'
    struct uci_section *port_s = uci_lookup_section(ctx, pkg, port_name);
    if (port_s && port_s->type && strcmp(port_s->type, "port") == 0) {
        memset(&ptr, 0, sizeof(ptr));
        ptr.package = "rule_mac";
        ptr.section = port_name;
        ptr.option = config_option;
        ptr.value = "0";
        if (uci_set(ctx, &ptr) != UCI_OK) {
            fprintf(stderr, "Lỗi: Không thể đặt %s='0' cho port '%s' (UCI error: %d).\n", config_option, port_name, ctx->err);
            success = 0;
        } else {
            printf("Đặt %s='0' cho port '%s' thành công.\n", config_option, port_name);
        }
    } else {
        fprintf(stderr, "Cảnh báo: Port section '%s' không tồn tại hoặc không phải section port.\n", port_name);
    }

    // Lưu và commit thay đổi
    if (success) {
        if (uci_save(ctx, pkg) != UCI_OK || uci_commit(ctx, &pkg, false) != UCI_OK) {
            fprintf(stderr, "Lỗi: Không thể commit thay đổi (UCI error: %d).\n", ctx->err);
            success = 0;
        }
    }

    uci_unload(ctx, pkg);
    
    if (success) {
        printf("Xóa port '%s_%s' khỏi list '%s' thành công.\n", port_name, direction, list_name);
    } else {
        fprintf(stderr, "Có lỗi xảy ra khi xóa port '%s_%s' khỏi list '%s'.\n", port_name, direction, list_name);
    }
}

// Hàm xóa toàn bộ rule trong list rồi xóa list (giống như delete_rule_from_list)
void clear_and_delete_list(struct uci_context *ctx, const char* list_name) {
    struct uci_package *pkg = NULL;
    struct uci_section *s;
    struct uci_option *opt;
    struct uci_element *e;
    char rule_names[100][256]; // Lưu tên các rule
    int rule_count = 0;

    if (!is_safe_string(list_name)) {
        printf("Lỗi: Tên list '%s' chứa ký tự không hợp lệ.\n", list_name);
        return;
    }
    if (!list_exists(ctx, list_name)) {
        printf("Lỗi: List '%s' không tồn tại.\n", list_name);
        return;
    }

    if (uci_load(ctx, "rule_mac", &pkg) != UCI_OK) {
        fprintf(stderr, "Lỗi: Không thể tải package rule_mac trong clear_and_delete_list.\n");
        return;
    }

    // Lấy danh sách tất cả rule và port trong list
    s = uci_lookup_section(ctx, pkg, list_name);
    if (!s || strcmp(s->type, "listmac") != 0) {
        fprintf(stderr, "Lỗi: Listmac '%s' không tồn tại.\n", list_name);
        uci_unload(ctx, pkg);
        return;
    }

    // Lưu danh sách các port cần dọn dẹp
    char port_names[MAX_PORTS][264]; // Lưu full port name
    int port_count = 0;
    
    struct uci_option *port_opt = uci_lookup_option(ctx, s, "port");
    if (port_opt && !uci_list_empty(&port_opt->v.list)) {
        uci_foreach_element(&port_opt->v.list, e) {
            if (port_count < MAX_PORTS) {
                strncpy(port_names[port_count], e->name, sizeof(port_names[port_count]) - 1);
                port_names[port_count][sizeof(port_names[port_count]) - 1] = '\0';
                port_count++;
            } else {
                fprintf(stderr, "Cảnh báo: Quá nhiều port trong list '%s' (giới hạn %d).\n", list_name, MAX_PORTS);
                break;
            }
        }
    }

    opt = uci_lookup_option(ctx, s, "rule");
    if (opt && !uci_list_empty(&opt->v.list)) {
        // Lưu tên các rule vào array
        uci_foreach_element(&opt->v.list, e) {
            if (rule_count < 100) {
                strncpy(rule_names[rule_count], e->name, sizeof(rule_names[rule_count]) - 1);
                rule_names[rule_count][sizeof(rule_names[rule_count]) - 1] = '\0';
                rule_count++;
            } else {
                fprintf(stderr, "Cảnh báo: Quá nhiều rule trong list '%s' (giới hạn 100).\n", list_name);
                break;
            }
        }
    }

    uci_unload(ctx, pkg);

    if (rule_count == 0) {
        printf("List '%s' không có rule nào để xóa.\n", list_name);
    } else {
        printf("Bắt đầu xóa %d rule khỏi list '%s' (bao gồm ethtool delete)...\n", rule_count, list_name);
        
        // Xóa từng rule khỏi list bằng delete_rule_from_list (có ethtool delete)
        for (int i = 0; i < rule_count; i++) {
            printf("Đang xóa rule '%s' khỏi list '%s' (%d/%d)...\n", rule_names[i], list_name, i + 1, rule_count);
            delete_rule_from_list(ctx, rule_names[i], list_name);
        }
        
        printf("Đã xóa tất cả rule khỏi list '%s'.\n", list_name);
    }

    // Kiểm tra xem list còn tồn tại không (có thể đã bị xóa bởi delete_rule_from_list)
    if (!list_exists(ctx, list_name)) {
        printf("List '%s' đã được xóa tự động khi xóa rule cuối cùng.\n", list_name);
        printf("Xóa toàn bộ list '%s' và tất cả rule (với ethtool delete) thành công.\n", list_name);
        return;
    }

    // Dọn dẹp tất cả các port trước khi xóa list
    if (port_count > 0) {
        printf("Đang dọn dẹp %d port khỏi list '%s'...\n", port_count, list_name);
        for (int i = 0; i < port_count; i++) {
            char port_name[256];
            char direction[8];
            
            // Parse port_name_direction
            char *underscore = strrchr(port_names[i], '_');
            if (underscore && (strcmp(underscore + 1, "in") == 0 || strcmp(underscore + 1, "out") == 0)) {
                strcpy(direction, underscore + 1);
                *underscore = '\0';
                strcpy(port_name, port_names[i]);
                
                printf("Dọn dẹp port '%s' direction '%s' (%d/%d)...\n", port_name, direction, i + 1, port_count);
                remove_port_from_list(ctx, list_name, port_name, direction);
            }
        }
        printf("Đã dọn dẹp tất cả port khỏi list '%s'.\n", list_name);
    }

    // Kiểm tra lại xem list còn tồn tại không trước khi xóa
    if (list_exists(ctx, list_name)) {
        printf("Đang xóa list '%s'...\n", list_name);
        delete_list(ctx, list_name);
        printf("Xóa toàn bộ list '%s' và tất cả rule (với ethtool delete) thành công.\n", list_name);
    } else {
        printf("List '%s' đã được xóa tự động.\n", list_name);
        printf("Xóa toàn bộ list '%s' và tất cả rule (với ethtool delete) thành công.\n", list_name);
    }
}

// Hàm hiển thị thông tin rule
void show_rule(struct uci_context *ctx, const char* rule_name) {
    struct uci_package *pkg = NULL;
    struct uci_section *s;
    struct uci_element *e;
    struct uci_option *opt;
    int found = 0;

    if (uci_load(ctx, "rule_mac", &pkg) != UCI_OK) {
        fprintf(stderr, "Lỗi: Không thể tải package rule_mac trong show_rule.\n");
        return;
    }

    if (rule_name) {
        // Hiển thị thông tin rule cụ thể
        if (!is_safe_string(rule_name)) {
            printf("Lỗi: Tên rule '%s' chứa ký tự không hợp lệ.\n", rule_name);
            uci_unload(ctx, pkg);
            return;
        }

        s = uci_lookup_section(ctx, pkg, rule_name);
        if (!s || strcmp(s->type, "rule") != 0) {
            printf("Rule '%s' không tồn tại.\n", rule_name);
            uci_unload(ctx, pkg);
            return;
        }

        printf("=== Thông tin Rule: %s ===\n", rule_name);
        
        // Hiển thị các thuộc tính của rule
        const char* attrs[] = {"srcmac", "dstmac", "protocol", "action", "priority"};
        for (int i = 0; i < 5; i++) {
            opt = uci_lookup_option(ctx, s, attrs[i]);
            if (opt) {
                printf("  %s: %s\n", attrs[i], opt->v.string);
            }
        }

        // Hiển thị danh sách list đang sử dụng rule này
        opt = uci_lookup_option(ctx, s, "used_by");
        if (opt && !uci_list_empty(&opt->v.list)) {
            printf("  Used by lists: ");
            int first = 1;
            uci_foreach_element(&opt->v.list, e) {
                if (!first) printf(", ");
                printf("%s", e->name);
                first = 0;
            }
            printf("\n");
        } else {
            printf("  Used by lists: (none)\n");
        }
        printf("\n");

    } else {
        // Hiển thị tất cả rule
        printf("=== Danh sách tất cả Rule ===\n");
        uci_foreach_element(&pkg->sections, e) {
            s = uci_to_section(e);
            if (strcmp(s->type, "rule") == 0) {
                found = 1;
                printf("Rule: %s\n", s->e.name);
                
                const char* attrs[] = {"srcmac", "dstmac", "protocol", "action", "priority"};
                for (int i = 0; i < 5; i++) {
                    opt = uci_lookup_option(ctx, s, attrs[i]);
                    if (opt) {
                        printf("  %s: %s\n", attrs[i], opt->v.string);
                    }
                }

                opt = uci_lookup_option(ctx, s, "used_by");
                if (opt && !uci_list_empty(&opt->v.list)) {
                    printf("  Used by: ");
                    int first = 1;
                    struct uci_element *list_e;
                    uci_foreach_element(&opt->v.list, list_e) {
                        if (!first) printf(", ");
                        printf("%s", list_e->name);
                        first = 0;
                    }
                    printf("\n");
                }
                printf("\n");
            }
        }
        if (!found) {
            printf("Không có rule nào.\n");
        }
    }

    uci_unload(ctx, pkg);
}

// Hàm hiển thị thông tin list
void show_list(struct uci_context *ctx, const char* list_name) {
    struct uci_package *pkg = NULL;
    struct uci_section *s;
    struct uci_element *e;
    struct uci_option *opt;
    int found = 0;

    if (uci_load(ctx, "rule_mac", &pkg) != UCI_OK) {
        fprintf(stderr, "Lỗi: Không thể tải package rule_mac trong show_list.\n");
        return;
    }

    if (list_name) {
        // Hiển thị thông tin list cụ thể
        if (!is_safe_string(list_name)) {
            printf("Lỗi: Tên list '%s' chứa ký tự không hợp lệ.\n", list_name);
            uci_unload(ctx, pkg);
            return;
        }

        s = uci_lookup_section(ctx, pkg, list_name);
        if (!s || strcmp(s->type, "listmac") != 0) {
            printf("List '%s' không tồn tại.\n", list_name);
            uci_unload(ctx, pkg);
            return;
        }

        printf("=== Thông tin List: %s ===\n", list_name);
        
        // Hiển thị ID
        opt = uci_lookup_option(ctx, s, "id");
        if (opt) {
            printf("  ID: %s\n", opt->v.string);
        }

        // Hiển thị danh sách rule
        opt = uci_lookup_option(ctx, s, "rule");
        if (opt && !uci_list_empty(&opt->v.list)) {
            printf("  Rules: ");
            int first = 1;
            uci_foreach_element(&opt->v.list, e) {
                if (!first) printf(", ");
                printf("%s", e->name);
                first = 0;
            }
            printf("\n");
        } else {
            printf("  Rules: (none)\n");
        }

        // Hiển thị danh sách port
        opt = uci_lookup_option(ctx, s, "port");
        if (opt && !uci_list_empty(&opt->v.list)) {
            printf("  Ports: ");
            int first = 1;
            uci_foreach_element(&opt->v.list, e) {
                if (!first) printf(", ");
                printf("%s", e->name);
                first = 0;
            }
            printf("\n");
        } else {
            printf("  Ports: (none)\n");
        }
        printf("\n");

    } else {
        // Hiển thị tất cả list
        printf("=== Danh sách tất cả List ===\n");
        uci_foreach_element(&pkg->sections, e) {
            s = uci_to_section(e);
            if (strcmp(s->type, "listmac") == 0) {
                found = 1;
                printf("List: %s\n", s->e.name);
                
                opt = uci_lookup_option(ctx, s, "id");
                if (opt) {
                    printf("  ID: %s\n", opt->v.string);
                }

                opt = uci_lookup_option(ctx, s, "rule");
                if (opt && !uci_list_empty(&opt->v.list)) {
                    // Đếm tổng số rule
                    int total_rules = 0;
                    struct uci_element *count_e;
                    uci_foreach_element(&opt->v.list, count_e) {
                        total_rules++;
                    }
                    
                    printf("  Rules (%d): ", total_rules);
                    int count = 0;
                    struct uci_element *rule_e;
                    uci_foreach_element(&opt->v.list, rule_e) {
                        if (count > 0) printf(", ");
                        printf("%s", rule_e->name);
                        count++;
                    }
                    printf("\n");
                } else {
                    printf("  Rules: (none)\n");
                }

                opt = uci_lookup_option(ctx, s, "port");
                if (opt && !uci_list_empty(&opt->v.list)) {
                    printf("  Ports: ");
                    int first = 1;
                    struct uci_element *port_e;
                    uci_foreach_element(&opt->v.list, port_e) {
                        if (!first) printf(", ");
                        printf("%s", port_e->name);
                        first = 0;
                    }
                    printf("\n");
                }
                printf("\n");
            }
        }
        if (!found) {
            printf("Không có list nào.\n");
        }
    }

    uci_unload(ctx, pkg);
}

// Hàm hiển thị thông tin port
void show_port(struct uci_context *ctx, const char* port_name) {
    struct uci_package *pkg = NULL;
    struct uci_section *s;
    struct uci_element *e;
    struct uci_option *opt;
    int found = 0;

    if (uci_load(ctx, "rule_mac", &pkg) != UCI_OK) {
        fprintf(stderr, "Lỗi: Không thể tải package rule_mac trong show_port.\n");
        return;
    }

    if (port_name) {
        // Hiển thị thông tin port cụ thể
        if (!is_safe_string(port_name)) {
            printf("Lỗi: Tên port '%s' chứa ký tự không hợp lệ.\n", port_name);
            uci_unload(ctx, pkg);
            return;
        }

        s = uci_lookup_section(ctx, pkg, port_name);
        if (!s || strcmp(s->type, "port") != 0) {
            printf("Port '%s' không tồn tại.\n", port_name);
            uci_unload(ctx, pkg);
            return;
        }

        printf("=== Thông tin Port: %s ===\n", port_name);
        
        // Hiển thị cấu hình in và out
        opt = uci_lookup_option(ctx, s, "config_in");
        if (opt) {
            if (strcmp(opt->v.string, "0") == 0) {
                printf("  Direction IN: (not configured)\n");
            } else {
                printf("  Direction IN: %s\n", opt->v.string);
            }
        } else {
            printf("  Direction IN: (not configured)\n");
        }

        opt = uci_lookup_option(ctx, s, "config_out");
        if (opt) {
            if (strcmp(opt->v.string, "0") == 0) {
                printf("  Direction OUT: (not configured)\n");
            } else {
                printf("  Direction OUT: %s\n", opt->v.string);
            }
        } else {
            printf("  Direction OUT: (not configured)\n");
        }
        printf("\n");

    } else {
        // Hiển thị tất cả port
        printf("=== Danh sách tất cả Port ===\n");
        uci_foreach_element(&pkg->sections, e) {
            s = uci_to_section(e);
            if (strcmp(s->type, "port") == 0) {
                found = 1;
                printf("Port: %s\n", s->e.name);
                
                opt = uci_lookup_option(ctx, s, "config_in");
                if (opt && strcmp(opt->v.string, "0") != 0) {
                    printf("  IN -> %s\n", opt->v.string);
                } else {
                    printf("  IN -> (not configured)\n");
                }

                opt = uci_lookup_option(ctx, s, "config_out");
                if (opt && strcmp(opt->v.string, "0") != 0) {
                    printf("  OUT -> %s\n", opt->v.string);
                } else {
                    printf("  OUT -> (not configured)\n");
                }
                printf("\n");
            }
        }
        if (!found) {
            printf("Không có port nào được cấu hình.\n");
        }
    }

    uci_unload(ctx, pkg);
}

// Hàm reload toàn bộ cấu hình từ UCI và apply ethtool
void reload_all_config(struct uci_context *ctx) {
    struct uci_package *pkg = NULL;
    struct uci_section *s;
    struct uci_element *e, *rule_e, *port_e;
    struct uci_option *opt;
    int success_count = 0;
    int error_count = 0;

    printf("=== Bắt đầu reload toàn bộ cấu hình ACL ===\n");

    if (uci_load(ctx, "rule_mac", &pkg) != UCI_OK) {
        fprintf(stderr, "Lỗi: Không thể tải package rule_mac trong reload_all_config.\n");
        return;
    }

    // Duyệt qua tất cả các listmac
    uci_foreach_element(&pkg->sections, e) {
        s = uci_to_section(e);
        if (strcmp(s->type, "listmac") != 0) {
            continue; // Bỏ qua các section không phải listmac
        }

        const char* list_name = s->e.name;
        printf("Đang xử lý list: %s\n", list_name);

        // Kiểm tra xem list có port không
        opt = uci_lookup_option(ctx, s, "port");
        if (!opt || uci_list_empty(&opt->v.list)) {
            printf("  List '%s' không có port nào, bỏ qua.\n", list_name);
            continue;
        }

        // Kiểm tra xem list có rule không
        struct uci_option *rule_opt = uci_lookup_option(ctx, s, "rule");
        if (!rule_opt || uci_list_empty(&rule_opt->v.list)) {
            printf("  List '%s' không có rule nào, bỏ qua.\n", list_name);
            continue;
        }

        // Duyệt qua tất cả các port của list
        uci_foreach_element(&opt->v.list, port_e) {
            const char* full_port_name = port_e->name;
            char port_name[256];
            char direction[8];
            
            // Tách port_name và direction
            if (sscanf(full_port_name, "%255[^_]_%7s", port_name, direction) != 2) {
                fprintf(stderr, "  Lỗi: Port '%s' không đúng định dạng, bỏ qua.\n", full_port_name);
                error_count++;
                continue;
            }

            if (strcmp(direction, "in") != 0 && strcmp(direction, "out") != 0) {
                fprintf(stderr, "  Lỗi: Direction '%s' không hợp lệ cho port '%s', bỏ qua.\n", direction, port_name);
                error_count++;
                continue;
            }

            printf("  Đang apply rule cho port: %s_%s\n", port_name, direction);

            // Duyệt qua tất cả các rule trong list và apply ethtool
            uci_foreach_element(&rule_opt->v.list, rule_e) {
                const char* rule_name = rule_e->name;
                printf("    Applying rule: %s\n", rule_name);
                
                if (calculate_loc(ctx, pkg, list_name, rule_name, direction, port_name) == 0) {
                    success_count++;
                } else {
                    fprintf(stderr, "    Lỗi: Không thể apply rule '%s' cho port '%s_%s'\n", 
                            rule_name, port_name, direction);
                    error_count++;
                }
            }
        }
    }

    uci_unload(ctx, pkg);
    
    printf("=== Hoàn thành reload cấu hình ===\n");
    printf("Thành công: %d rule\n", success_count);
    printf("Lỗi: %d rule\n", error_count);
    
    if (error_count == 0) {
        printf("Tất cả cấu hình đã được apply thành công!\n");
    } else {
        printf("Có %d lỗi xảy ra trong quá trình reload.\n", error_count);
    }
}

int main(int argc, char* argv[]) {
    struct uci_context *ctx = uci_alloc_context();
    if (!ctx) {
        fprintf(stderr, "Lỗi: Không thể khởi tạo UCI context.\n");
        return 1;
    }

    if (argc < 2) {
        fprintf(stderr, "Sử dụng:\n");
        fprintf(stderr, "  %s add_rule <rule_name> <srcmac> <dstmac> <protocol> <action> <priority>\n", argv[0]);
        fprintf(stderr, "  %s add_list <list_name> <default_rule_type>\n", argv[0]);
        fprintf(stderr, "  %s add_rule_to_list <rule_name> <list_name>\n", argv[0]);
        fprintf(stderr, "  %s add_list_to_port <list_name> <port_name> <in/out>\n", argv[0]);
        fprintf(stderr, "  %s delete_rule <rule_name>\n", argv[0]);
        fprintf(stderr, "  %s delete_rule_from_list <rule_name> <list_name>\n", argv[0]);
        fprintf(stderr, "  %s delete_list <list_name>\n", argv[0]);
        fprintf(stderr, "  %s clear_and_delete_list <list_name>\n", argv[0]);
        fprintf(stderr, "  %s remove_port_from_list <list_name> <port_name> <in/out>\n", argv[0]);
        fprintf(stderr, "  %s show_rule [rule_name]\n", argv[0]);
        fprintf(stderr, "  %s show_list [list_name]\n", argv[0]);
        fprintf(stderr, "  %s show_port [port_name]\n", argv[0]);
        fprintf(stderr, "  %s reload\n", argv[0]);
        uci_free_context(ctx);
        return 1;
    }

    if (strcmp(argv[1], "add_rule") == 0) {
        if (argc != 8) {
            fprintf(stderr, "Sử dụng: %s add_rule <rule_name> <srcmac> <dstmac> <protocol> <action> <priority>\n", argv[0]);
            uci_free_context(ctx);
            return 1;
        }
        int priority = atoi(argv[7]);
        add_rule(ctx, argv[2], argv[3], argv[4], argv[5], argv[6], priority);
    } else if (strcmp(argv[1], "add_list") == 0) {
        if (argc != 4) {
            fprintf(stderr, "Sử dụng: %s add_list <list_name> <default_rule_type>\n", argv[0]);
            fprintf(stderr, "  <default_rule_type> phải là 'blockall' hoặc 'accept_all'\n");
            uci_free_context(ctx);
            return 1;
        }
        add_list(ctx, argv[2], argv[3]);
    } else if (strcmp(argv[1], "add_rule_to_list") == 0) {
        if (argc != 4) {
            fprintf(stderr, "Sử dụng: %s add_rule_to_list <rule_name> <list_name>\n", argv[0]);
            uci_free_context(ctx);
            return 1;
        }
        add_rule_to_list(ctx, argv[2], argv[3]);
    } else if (strcmp(argv[1], "add_list_to_port") == 0) {
        if (argc != 5) {
            fprintf(stderr, "Sử dụng: %s add_list_to_port <list_name> <port_name> <in/out>\n", argv[0]);
            uci_free_context(ctx);
            return 1;
        }
        add_list_to_port(ctx, argv[2], argv[3], argv[4]);
    } else if (strcmp(argv[1], "delete_rule") == 0) {
        if (argc != 3) {
            fprintf(stderr, "Sử dụng: %s delete_rule <rule_name>\n", argv[0]);
            uci_free_context(ctx);
            return 1;
        }
        delete_rule(ctx, argv[2]);
    } else if (strcmp(argv[1], "delete_rule_from_list") == 0) {
        if (argc != 4) {
            fprintf(stderr, "Sử dụng: %s delete_rule_from_list <rule_name> <list_name>\n", argv[0]);
            uci_free_context(ctx);
            return 1;
        }
        delete_rule_from_list(ctx, argv[2], argv[3]);
    } else if (strcmp(argv[1], "delete_list") == 0) {
        if (argc != 3) {
            fprintf(stderr, "Sử dụng: %s delete_list <list_name>\n", argv[0]);
            uci_free_context(ctx);
            return 1;
        }
        delete_list(ctx, argv[2]);
    } else if (strcmp(argv[1], "remove_port_from_list") == 0) {
        if (argc != 5) {
            fprintf(stderr, "Sử dụng: %s remove_port_from_list <list_name> <port_name> <in/out>\n", argv[0]);
            uci_free_context(ctx);
            return 1;
        }
        remove_port_from_list(ctx, argv[2], argv[3], argv[4]);
    } else if (strcmp(argv[1], "clear_and_delete_list") == 0) {
        if (argc != 3) {
            fprintf(stderr, "Sử dụng: %s clear_and_delete_list <list_name>\n", argv[0]);
            uci_free_context(ctx);
            return 1;
        }
        clear_and_delete_list(ctx, argv[2]);
    } else if (strcmp(argv[1], "show_rule") == 0) {
        if (argc == 2) {
            show_rule(ctx, NULL); // Hiển thị tất cả rule
        } else if (argc == 3) {
            show_rule(ctx, argv[2]); // Hiển thị rule cụ thể
        } else {
            fprintf(stderr, "Sử dụng: %s show_rule [rule_name]\n", argv[0]);
            uci_free_context(ctx);
            return 1;
        }
    } else if (strcmp(argv[1], "show_list") == 0) {
        if (argc == 2) {
            show_list(ctx, NULL); // Hiển thị tất cả list
        } else if (argc == 3) {
            show_list(ctx, argv[2]); // Hiển thị list cụ thể
        } else {
            fprintf(stderr, "Sử dụng: %s show_list [list_name]\n", argv[0]);
            uci_free_context(ctx);
            return 1;
        }
    } else if (strcmp(argv[1], "show_port") == 0) {
        if (argc == 2) {
            show_port(ctx, NULL); // Hiển thị tất cả port
        } else if (argc == 3) {
            show_port(ctx, argv[2]); // Hiển thị port cụ thể
        } else {
            fprintf(stderr, "Sử dụng: %s show_port [port_name]\n", argv[0]);
            uci_free_context(ctx);
            return 1;
        }
    } else if (strcmp(argv[1], "reload") == 0) {
        if (argc != 2) {
            fprintf(stderr, "Sử dụng: %s reload\n", argv[0]);
            uci_free_context(ctx);
            return 1;
        }
        reload_all_config(ctx);
    } else {
        fprintf(stderr, "Lệnh không hợp lệ: %s\n", argv[1]);
        uci_free_context(ctx);
        return 1;
    }

    uci_free_context(ctx);
    return 0;
}