#include <tuple>
#include <string>
#include <mysqlx/xdevapi.h>
#include <mysqlx/common.h>
#include <iostream>
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <openssl/sha.h>
namespace asio = boost::asio;
namespace Polus{
enum class RegistState : std::size_t{
    Ok, AlreadyRegistered, UncorrectLoginOrPassword
};
struct TableBasicData{
    std::u16string dbName;
    std::u16string tableName;
};
//почта, username, password
using RegData = std::tuple<std::u16string, std::u16string, std::u16string>;
class AuthTempl {
private:
    TableBasicData dataBaseTempl;
    std::unique_ptr<mysqlx::Session> session;
    bool IsInclude(const RegData& data, mysqlx::Table& table) const;
public:
    AuthTempl(const TableBasicData& db);
    RegistState TryToRegistr(const RegData& data, std::string_view globalSalt) const;
};
}
