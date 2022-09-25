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
    std::wstring dbName;
    std::wstring tableName;
};
//почта, username, password
using RegData = std::tuple<std::wstring, std::wstring, std::wstring>;
class AuthTempl {
private:
    TableBasicData dataBaseTempl;
    std::unique_ptr<mysqlx::Session> session;
    bool IsInclude(const RegData& data, mysqlx::Table& table) const;
public:
    AuthTempl(const TableBasicData& db);
    RegistState TryToRegistr(const RegData& data) const;
};
}
