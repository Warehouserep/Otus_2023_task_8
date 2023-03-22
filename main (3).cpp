#include <iostream>
#include <boost/filesystem/operations.hpp>
#include <boost/filesystem/fstream.hpp>
#include <boost/program_options.hpp>

#include <boost/algorithm/hex.hpp>
#include <boost/uuid/detail/md5.hpp>
#include <boost/uuid/detail/sha1.hpp>

#include <boost/regex.hpp>

#include <vector>

#define BLOCK_SIZE 10

using namespace boost::filesystem;
using namespace std;

namespace po = boost::program_options;

typedef struct {
    vector<string> files;
    vector<string> digests;
} FileGroup;

enum DigestAlg {
    SHA1,
    MD5
};

vector<FileGroup> file_groups;
vector<string> file_masks;
vector<string> exclude_dirs;
unsigned min_file_size = 1;
DigestAlg d_algo = SHA1;

const char  *c_dir_option_name = "dirs",
            *c_exclude_dir_option_name = "excld",
            *c_depth_option_name = "depth",
            *c_masks_option_name = "masks",
            *c_min_size_option_name = "msize",
            *c_algorithm_option_name = "alg";

void GetMd5(std::string &str_md5, const char * const buffer, size_t buffer_size) {
    boost::uuids::detail::md5 boost_md5;
    boost_md5.process_bytes(buffer, buffer_size);
    boost::uuids::detail::md5::digest_type digest;
    boost_md5.get_digest(digest);
    const auto char_digest = reinterpret_cast<const char*>(&digest);
    str_md5.clear();
    boost::algorithm::hex(char_digest,char_digest+sizeof(boost::uuids::detail::md5::digest_type), std::back_inserter(str_md5));
}

void GetSHA1(std::string &str_sha1, const char * const buffer, size_t buffer_size) {
    char hash[20];
    boost::uuids::detail::sha1 boost_sha1;
    boost_sha1.process_bytes(buffer, buffer_size);
    boost::uuids::detail::sha1::digest_type digest;
    boost_sha1.get_digest(digest);
    for(int i = 0; i < 5; ++i) {
        const char *tmp = reinterpret_cast<char*>(digest);
        hash[i*4] = tmp[i*4+3];
        hash[i*4+1] = tmp[i*4+2];
        hash[i*4+2] = tmp[i*4+1];
        hash[i*4+3] = tmp[i*4];
    }

    str_sha1.clear();
    std::ostringstream buf;
    for(int i = 0; i < 20; ++i) {
        buf << setiosflags(ios::uppercase) << std::hex << ((hash[i] & 0x0000000F0) >> 4);
        buf << setiosflags(ios::uppercase) << std::hex << (hash[i] & 0x00000000F);
    }

    str_sha1 = buf.str();
}

po::variables_map process_program_options(const int argc, const char *const argv[])
{
    po::options_description desc("Allowed options");
    desc.add_options()
        (c_dir_option_name, po::value<vector<string>>(), "Dirs for scan")
        (c_exclude_dir_option_name, po::value<vector<string>>(), "Exclude dirs for scan")
        (c_depth_option_name, po::value<unsigned int>(), "Scan depth")
        (c_masks_option_name, po::value<vector<string>>(), "File masks")
        (c_min_size_option_name, po::value<unsigned int>(), "Minimum file size")
        (c_algorithm_option_name, po::value<string>(), "Algorithms (SHA1 | MD5)")
        ("help", "Help guid")
    ;

    po::variables_map args;

    try {
        po::store(
            po::parse_command_line(argc, argv, desc),
            args
        );
    }
    catch (po::error const& e) {
        std::cerr << e.what() << '\n';
        exit( EXIT_FAILURE );
    }
    po::notify(args);

    if (args.count("help")) {
      cout << desc << "\n";
    }
    return args;
}

unsigned get_file_size(std::ifstream* file) {
    const auto begin = file->tellg();
    file->seekg (0, ios::end);
    const auto end = file->tellg();
    file->seekg (0, ios::beg);
    return end - begin;
}

void handle_file(const path& file_path) {
    static shared_ptr<char> buff(new char[BLOCK_SIZE]);

    {
        boost::smatch what;
        bool found = false;
        for(auto& f:file_masks) {
            const boost::regex my_filter(f.c_str());
            if(boost::regex_match( string(file_path.leaf().c_str()), what, my_filter)) {
                found = true;
                break;
            }
        }
        if (!found) return;
    }

    std::ifstream file;
    file.open(file_path.c_str(), ios::in | ios::binary);
    if (!file || get_file_size(&file) < min_file_size) {
        return;
    }
    std::string digest;
    vector<FileGroup*> fgroups;
    for(size_t i=0;i<file_groups.size();i++) {
        fgroups.push_back(&file_groups[i]);
    }

    FileGroup newGroup;
    size_t block_index = 0;
    while (1) {
        digest = "";
        memset((void*)buff.get(), 0, BLOCK_SIZE);
        file.get(buff.get(), BLOCK_SIZE);
        if (!file) break;
        switch(d_algo) {
            case SHA1:
                GetSHA1(digest, buff.get(), BLOCK_SIZE);
            break;
            case MD5:
                GetMd5(digest,buff.get(), BLOCK_SIZE);
            break;
            default:
                throw logic_error("wrong digest func");
            break;
        }
        for(size_t i=0;i<fgroups.size();i++) {
            auto c_group = fgroups[i];
            if (c_group->digests.size() < (block_index + 1) || c_group->digests[block_index] != digest) {
                fgroups.erase(fgroups.begin() + i);
                i--;
            }
        }
        newGroup.digests.push_back(std::move(digest));
        block_index++;
    }
    if (!fgroups.size() || fgroups[0]->digests.size() != block_index) {
        newGroup.files.push_back(file_path.c_str());
        file_groups.push_back(newGroup);
    } else {
        fgroups[0]->files.push_back(file_path.c_str());
    }
    file.close();
}

void handle_dir(path dir_path, int depth, int max_depth) {
    if (depth > max_depth) return;

    if (!exists(dir_path)) return;
    for(auto& exp: exclude_dirs) {
        if (path(exp) == dir_path)
            return;
    }

    directory_iterator end_itr;
    for ( directory_iterator itr( dir_path ); itr != end_itr; ++itr) {
      if(is_directory(itr->status()) ) {
          handle_dir(itr->path(), depth+1, max_depth);
      } else {
          handle_file(itr->path());
      }
    }
}

int main(int argc, char *const argv[])
{
    auto args = process_program_options(argc, argv);

    vector<string> dirs;
    if (!args.count(c_dir_option_name)) {
        return 1;
    }
    dirs = args["dirs"].as<vector<string>>();
    if (!dirs.size()) return 1;

    if (args.count(c_exclude_dir_option_name)) {
        exclude_dirs = args[c_exclude_dir_option_name]
                .as<vector<string>>();
    }

    unsigned max_depth = 1;
    if (args.count(c_depth_option_name)) {
        max_depth = args[c_depth_option_name]
                .as<unsigned>();
    }

    if (args.count(c_masks_option_name)) {
        file_masks = args[c_masks_option_name]
                .as<vector<string>>();
    }

    if (args.count(c_min_size_option_name)) {
        min_file_size = args[c_min_size_option_name]
                .as<unsigned int>();
    }

    if (args.count(c_algorithm_option_name)) {
        string algo = args[c_algorithm_option_name]
                .as<string>();
        if (algo == "MD5")
            d_algo = MD5;
    }

    for(const auto& cdir: dirs) {
        handle_dir(cdir, 0, max_depth);
    }

    for(size_t i=0;i<file_groups.size();i++) {
        for(size_t j=0;j<file_groups[i].files.size();j++)
            cout << file_groups[i].files[j] << endl;
        cout << endl;
    }
    return 0;
}
