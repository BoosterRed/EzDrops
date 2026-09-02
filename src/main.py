"""EzDrops — 블리자드/배틀넷 드롭스 리딤 코드 다중 등록 도구.

여러 개의 리딤 코드를 각각 독립된 브라우저 창에 나눠 넣어두고, 마지막 "확인" 버튼만
원하는 시점에 전 창 동시에 누를 수 있게 해주는 데스크톱 유틸리티.

면책 조항
    이 프로그램은 Blizzard Entertainment와 아무런 관련이 없는 비공식 개인 제작 도구이며,
    어떠한 보증도 없이(AS-IS) 공개됩니다. 사용으로 인해 발생하는 모든 결과 — 계정 제재,
    리딤 코드 소실, 그 밖의 손해를 포함하되 이에 한정되지 않음 — 에 대한 책임은 전적으로
    사용자 본인에게 있으며, 제작자는 어떠한 책임도 지지 않습니다. 사용 전 Blizzard의
    이용약관을 직접 확인하시고, 본인 소유의 코드와 본인 계정에만 사용하십시오.
    자세한 내용은 README.md와 LICENSE(MIT)를 참조하십시오.

계정 정보 취급
    자동 로그인 이메일/비밀번호는 디스크나 로그에 절대 저장되지 않고, 해당 실행의
    메모리에서만 사용된 뒤 입력란도 즉시 비워집니다. 다만 브라우저 로그인 세션은
    실행 중 browser_profiles 폴더에 저장되며 앱을 정상 종료할 때 삭제됩니다
    (강제 종료 시에는 남을 수 있음).

    리딤 코드는 v1.9.18부터 로그(run_log.txt 및 화면 로그)에 부분 마스킹되어 남습니다.
    v1.9.19부터는 코드 전체를 담던 results.csv를 없애고, 중복 등록 확인용 기록
    (registered_codes.txt)에 되돌릴 수 없는 SHA-256 지문만 저장합니다. 즉 이 프로그램이
    디스크에 남기는 파일 중 리딤 코드 원본을 담는 것은 하나도 없습니다.
"""
import hashlib
import os
import secrets
import sys


def get_base_dir():
    """실행 파일 위치 또는 스크립트 위치를 반환.
    run_log.txt, browser_profiles처럼 '쓰기'가 필요한 것들의 기준 경로 — 반드시 exe 옆이어야
    사용자가 로그를 바로 찾을 수 있다."""
    if getattr(sys, 'frozen', False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))


def get_resource_dir():
    """번들에 동봉된 읽기 전용 리소스(아이콘 등)의 기준 경로를 반환.
    PyInstaller onedir 빌드에서는 sys._MEIPASS가 _internal 폴더를 가리킨다 — 리소스를 그 안에
    넣어두면 exe 옆(루트)이 실행 파일 하나로 깔끔하게 유지된다. 개발 중(비frozen)에는
    스크립트 폴더를 그대로 쓴다."""
    if getattr(sys, 'frozen', False):
        return getattr(sys, '_MEIPASS', os.path.dirname(sys.executable))
    return os.path.dirname(os.path.abspath(__file__))


def mask_code(code, keep=4):
    """로그에 남길 리딤 코드를 부분 마스킹한다.

    run_log.txt는 "문제가 생기면 이 파일을 그대로 보내면 된다"는 전제로 만든 파일이라, 코드가
    통째로 찍히면 그 파일 하나로 리딤 코드가 유출된다. 화면 로그도 캡처해서 공유되는 일이
    잦으므로 동일하게 적용한다. 어느 코드인지 구분할 만큼만 남기고 나머지는 가린다.

    글자 수를 함께 남기는 건, 이 프로그램에서 실제로 겪은 버그 상당수가 붙여넣기 과정에서
    코드가 잘리거나 이어붙는 문제였기 때문 — 길이만 봐도 그 유형인지 바로 판단할 수 있다.
    """
    code = (code or "").strip()
    if len(code) <= keep:
        return "*" * len(code)
    return f"{code[:keep]}***({len(code)}자)"


REGISTRY_FILENAME = "registered_codes.txt"
REGISTRY_HEADER = (
    "# EzDrops 중복 등록 방지 기록\n"
    "# 리딤 코드 원본은 저장하지 않습니다. 아래 값들은 코드를 SHA-256으로 변환한 결과이며,\n"
    "# 이 파일만으로는 원래 코드를 되돌릴 수 없습니다(복호화가 아니라 단방향 변환입니다).\n"
    "# 같은 코드인지 비교하는 용도로만 쓰입니다.\n"
)


def code_fingerprint(code, salt):
    """리딤 코드를 되돌릴 수 없는 지문으로 바꾼다.

    설치마다 다른 salt를 앞에 붙여서 해시한다. 코드 자체의 경우의 수가 이미 방대하지만,
    salt가 있으면 미리 계산해둔 표로 대조하는 방식 자체가 성립하지 않는다.
    """
    return hashlib.sha256((salt + code.strip()).encode("utf-8")).hexdigest()


def load_registry(path):
    """(salt, 지문 집합)을 반환한다. 파일이 없으면 salt를 새로 만들어 돌려준다.

    읽기에 실패해도 예외를 올리지 않는다 — 중복 확인은 어디까지나 편의 기능이라,
    이것 때문에 등록 자체가 막히면 안 된다.
    """
    salt, prints = None, set()
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line.startswith("# salt="):
                    salt = line[len("# salt="):].strip()
                elif line and not line.startswith("#"):
                    prints.add(line)
    except FileNotFoundError:
        pass
    except Exception:
        return secrets.token_hex(16), set()
    return (salt or secrets.token_hex(16)), prints


def append_registry(path, salt, new_prints):
    """새로 등록 성공한 코드의 지문을 기록에 덧붙인다. 실패해도 조용히 넘어간다."""
    if not new_prints:
        return
    try:
        fresh = not os.path.exists(path)
        with open(path, "a", encoding="utf-8") as f:
            if fresh:
                f.write(REGISTRY_HEADER)
                f.write(f"# salt={salt}\n")
            for p in new_prints:
                f.write(p + "\n")
    except Exception:
        pass


MAX_GRID_COLUMNS = 5      # 한 줄에 놓을 창의 최대 개수
MAX_WINDOW_WIDTH = 1280   # 창 하나의 최대 크기. 화면이 넉넉해도 이보다 크게 키우지는 않는다.
MAX_WINDOW_HEIGHT = 720
MIN_WINDOW_WIDTH = 640    # 이보다 좁아지면 사이트가 모바일 레이아웃으로 바뀔 수 있어 하한을 둔다.
MIN_WINDOW_HEIGHT = 480
MIN_VISIBLE_X = 200       # 창이 겹치더라도 앞쪽 이만큼은 보이게 한다(어느 창인지 구분용).
MIN_VISIBLE_Y = 200


def compute_window_layout(count, screen_w, screen_h):
    """창 개수와 화면 크기로 (창 너비, 창 높이, [(x, y), ...])를 계산한다.

    v1.9.20 이전에는 창 크기(1280x720)와 열 수(3)가 상수로 박혀 있어서, 화면이 좁거나 코드가
    많으면 아래쪽 창이 화면 밖으로 나가 눈으로 확인할 수 없었다(2560x1440에서도 7번째 창부터
    잘림). 여기서는 반대로 화면에서 출발해 창 크기와 간격을 역산한다.

    보장하는 것: 모든 창이 화면 안에 완전히 들어온다. 창이 겹치더라도 각 창의 앞부분
    MIN_VISIBLE_X/Y 만큼은 다음 창에 가려지지 않는다.

    순수 함수로 둔 이유는 Tk나 브라우저 없이 여러 해상도를 그대로 검증하기 위함이다.
    """
    count = max(1, count)
    cols = min(count, MAX_GRID_COLUMNS)
    rows = -(-count // cols)  # 올림 나눗셈

    # 창 크기: 화면에 다 넣으려면 겹침 간격(MIN_VISIBLE)만큼은 자리를 비워둬야 한다.
    win_w = min(MAX_WINDOW_WIDTH, screen_w - MIN_VISIBLE_X * (cols - 1))
    win_h = min(MAX_WINDOW_HEIGHT, screen_h - MIN_VISIBLE_Y * (rows - 1))
    # 화면이 너무 좁아 하한을 지킬 수 없으면, 화면 밖으로 내보내느니 하한을 택한다.
    win_w = max(MIN_WINDOW_WIDTH, win_w)
    win_h = max(MIN_WINDOW_HEIGHT, win_h)

    # 남는 공간을 창 사이에 균등 분배한다. 한 줄에 하나뿐이면 나눌 필요가 없다.
    gap_x = (screen_w - win_w) // (cols - 1) if cols > 1 else 0
    gap_y = (screen_h - win_h) // (rows - 1) if rows > 1 else 0

    positions = []
    for i in range(count):
        col, row = i % cols, i // cols
        # 하한 때문에 창이 화면보다 클 수 있다. 그 경우 음수 좌표가 되지 않게 0으로 붙인다.
        positions.append((max(0, col * gap_x), max(0, row * gap_y)))
    return win_w, win_h, positions


def scrub_codes(text, codes):
    """예외 메시지처럼 우리가 만들지 않은 문자열에서 리딤 코드를 찾아 마스킹으로 바꾼다.

    Playwright 오류 메시지가 입력값을 포함하는지는 버전에 따라 달라질 수 있다 — 포함되지
    않는다고 추정하고 넘어가는 대신, 로그에 남기기 직전에 무조건 한 번 걸러낸다.
    """
    text = str(text)
    for code in codes or ():
        code = (code or "").strip()
        if code and code in text:
            text = text.replace(code, mask_code(code))
    return text


# exe 배포 시 옆에 동봉한 ms-playwright 폴더의 크로미움을 사용 (최초 다운로드 불필요)
_bundled_browsers = os.path.join(get_base_dir(), "ms-playwright")
if os.path.isdir(_bundled_browsers):
    os.environ["PLAYWRIGHT_BROWSERS_PATH"] = _bundled_browsers

import tkinter as tk
from tkinter import scrolledtext, messagebox
import threading
import asyncio
import queue
import time
import shutil
from playwright.async_api import async_playwright

# 버전 이력 (요약)
# 각 버전에서 실제로 무엇이 문제였고 어떻게 확인했는지는 CHANGELOG.md에 전부 남아 있다.
# 여기에는 흐름만 남긴다.
#
# 1.0.x        최초 동작. 등록 URL 오류, Windows 이벤트 루프 정책 때문에 브라우저가 아예 안 뜨던
#              문제, 완료 직후 브라우저가 닫히던 문제 등 치명적 버그 해소.
# 1.1~1.2      "코드 등록" 후 확인 화면이 한 번 더 뜨는 2단계 구조 대응, 수동 동시 확인 버튼 추가.
# 1.3.x        다중 탭 동시성 문제. 탭이 한꺼번에 이동하면 일부가 타임아웃으로 실패하는 것을 실측해
#              domcontentloaded 기준으로 변경. 고정 대기 대신 네트워크가 잠잠해질 때까지 대기.
# 1.4~1.5      "리디렉션 횟수 초과" 장기 추적. 시차 조정, 순차 처리, 타임아웃 상향을 차례로
#              시도했으나 전부 근본 해결이 아니었음.
# 1.6.0        구조 변경 — 코드마다 완전히 독립된 브라우저 프로필을 써서 세션 경합 자체를 제거.
#              대신 로그인이 창마다 필요해져 자동 로그인(1.6.3)과 창 배치(1.6.7~)가 따라붙음.
# 1.7.x        창 격자 배치, 배치 종료 후 열려있는 창 재사용.
# 1.9.0        대폭 단순화 — 결과 화면을 읽어 성공/실패를 판정하고 재제출하던 로직을 전부 제거.
#              이미 성공한 코드를 또 제출하던 버그가 근본적으로 사라짐.
# 1.9.1        번들 크로미움(약 430MB)을 빼고 PC에 설치된 구글 크롬을 사용해 배포 용량을 크게 줄임.
#              대신 대상 PC에 크롬이 설치돼 있어야 한다.
# 1.9.2        공식 이름을 EzDrops로 확정.
# 1.9.5        앱 종료 시 저장된 로그인 세션을 전부 삭제 — 다음 실행 땐 항상 새로 로그인한다.
# 1.9.9~1.9.15 창/작업표시줄 아이콘이 흐린 문제 추적. 최종 원인은 iconbitmap()이 다중 해상도
#              .ico에서 프레임 하나만 골라 늘려 쓰는 API 한계였음 — 크기별 PNG + iconphoto()로 교체.
# 1.9.16       배포 폴더 정리 — 아이콘을 _internal 안으로 옮겨 배포 루트를 exe 하나로 유지.
# 1.9.17       창별 자동 로그인 간격을 GUI에서 조절 가능하게 함(기본 5초, 0이면 전부 동시).
# 1.9.18       로그에 리딤 코드가 통째로 남지 않도록 부분 마스킹(앞 4자 + 글자 수). 예외 메시지도
#              로그 직전에 한 번 걸러낸다. 오픈소스 공개를 앞두고 run_log.txt가 그대로
#              전달되는 상황을 전제로 한 조치.
# 1.9.19       코드 전체를 담던 results.csv를 없애고, 되돌릴 수 없는 SHA-256 지문만 쌓는
#              중복 등록 방지 기록(registered_codes.txt)으로 대체. 시작할 때 입력 코드와
#              대조해 "이미 등록한 코드"를 알려준다. GUI 체크박스로 끌 수 있다.
# 1.9.20       창 배치를 화면 해상도에서 역산하도록 변경(최대 5열). 이전에는 창 크기 1280x720과
#              3열이 상수로 박혀 있어 2560x1440에서도 7번째 창부터 화면 밖으로 나갔다. 이제
#              모든 창이 화면 안에 들어오고, 겹치더라도 앞쪽 200px은 항상 보인다.
APP_VERSION = "1.9.20"

# 창별 자동 로그인 시도 간격의 기본값(초). v1.9.17부터 GUI에서 바꿀 수 있고, 이 값은
# 입력이 비었거나 숫자가 아닐 때 되돌아가는 기준점으로만 쓰인다.
DEFAULT_LOGIN_STAGGER_SECONDS = 5
# 입력 가능한 범위. 0은 "시차 없이 전부 동시"를 의미한다.
MIN_LOGIN_STAGGER_SECONDS = 0
MAX_LOGIN_STAGGER_SECONDS = 60

class EzDropsApp:
    def __init__(self, root):
        self.root = root
        self.root.title(f"EzDrops v{APP_VERSION}")
        self.root.geometry("600x820")
        self.log_file_path = os.path.join(get_base_dir(), "run_log.txt")
        self.registry_path = os.path.join(get_base_dir(), REGISTRY_FILENAME)
        # 화면 크기는 Tk 메인스레드에서만 안전하게 읽을 수 있어서 시작 시점에 한 번 받아둔다.
        # 브라우저 배치 계산은 백그라운드 스레드에서 돌기 때문에 거기서 직접 읽으면 안 된다.
        self.screen_w = root.winfo_screenwidth()
        self.screen_h = root.winfo_screenheight()

        try:
            # iconbitmap(단일 .ico)은 Windows에서 프레임 하나만 가져다 자체적으로(저품질로)
            # 늘리거나 줄여써서 항상 흐리게 나오는 문제가 있었음 — WM_GETICON으로 직접 확인해
            # 확정. 크기별 PNG를 각각 로드해 iconphoto에 통째로 넘기면 Tk/Windows가 상황에
            # 맞는 크기를 그대로 골라 쓸 수 있어 훨씬 선명하다.
            icon_images = [
                tk.PhotoImage(file=os.path.join(get_resource_dir(), f"icon_{s}.png"))
                for s in (16, 24, 32, 48, 64, 128, 256)
            ]
            self.root.iconphoto(True, *icon_images)
            self._icon_images = icon_images  # 가비지 컬렉션 방지용 참조 보관
        except Exception:
            pass  # 아이콘 파일이 없어도(개발 중 등) 앱 실행 자체는 막지 않는다

        # --- UI 구성 ---
        # 자동 로그인 (선택 사항) — 저장되지 않고 이번 실행 동안만 메모리에서 사용됨
        login_frame = tk.Frame(root)
        login_frame.pack(pady=(10, 0))
        tk.Label(login_frame, text="자동 로그인(선택, 저장 안 됨) 이메일:").grid(row=0, column=0, padx=(0, 4))
        self.login_email_entry = tk.Entry(login_frame, width=22)
        self.login_email_entry.grid(row=0, column=1, padx=(0, 10))
        tk.Label(login_frame, text="비밀번호:").grid(row=0, column=2, padx=(0, 4))

        # 비밀번호 입력칸 + 눈 모양 아이콘을 하나의 입력창처럼 보이게 테두리 있는 프레임으로 묶는다.
        pw_box = tk.Frame(login_frame, relief="solid", bd=1, bg="white")
        pw_box.grid(row=0, column=3)
        self.login_password_entry = tk.Entry(pw_box, width=14, show="*", relief="flat", highlightthickness=0, bd=0)
        self.login_password_entry.pack(side=tk.LEFT, ipady=2, padx=(4, 0))
        # 누르고 있는 동안만 비밀번호가 보이고, 떼면 바로 다시 마스킹된다.
        self.show_password_btn = tk.Label(pw_box, text="\U0001F441", bg="white", cursor="hand2")
        self.show_password_btn.pack(side=tk.LEFT, padx=(2, 4))
        self.show_password_btn.bind("<ButtonPress-1>", lambda e: self.login_password_entry.config(show=""))
        self.show_password_btn.bind("<ButtonRelease-1>", lambda e: self.login_password_entry.config(show="*"))

        # 창별 자동 로그인 간격 — 배틀넷 인증기 앱 승인처럼 폰을 직접 들어서 눌러야 하는 2FA는
        # 사람마다/상황마다 걸리는 시간이 달라서, 코드에 박아두지 않고 직접 조절하게 둔다.
        tk.Label(login_frame, text="창별 로그인 간격(초):").grid(
            row=1, column=0, padx=(0, 4), pady=(8, 0), sticky="e")
        self.login_stagger_var = tk.StringVar(value=str(DEFAULT_LOGIN_STAGGER_SECONDS))
        self.login_stagger_spin = tk.Spinbox(
            login_frame, from_=MIN_LOGIN_STAGGER_SECONDS, to=MAX_LOGIN_STAGGER_SECONDS,
            increment=1, width=6, justify="center", textvariable=self.login_stagger_var,
        )
        self.login_stagger_spin.grid(row=1, column=1, sticky="w", pady=(8, 0))
        tk.Label(
            login_frame, text=f"기본 {DEFAULT_LOGIN_STAGGER_SECONDS}초 · 0이면 전부 동시",
            font=("Arial", 8), fg="#666666",
        ).grid(row=1, column=2, columnspan=2, sticky="w", padx=(4, 0), pady=(8, 0))

        # 중복 등록 방지 기록 — 코드 원본이 아니라 되돌릴 수 없는 지문만 남긴다.
        self.dup_check_var = tk.BooleanVar(value=True)
        tk.Checkbutton(
            login_frame, text="이미 등록한 코드 확인", variable=self.dup_check_var,
        ).grid(row=2, column=0, columnspan=2, sticky="w", pady=(6, 0))

        # 설명은 login_frame 안에 넣으면 그리드 열이 문구 길이만큼 넓어져서 비밀번호 칸이
        # 창 밖으로 밀려난다(실측 확인) — 프레임 바깥의 독립된 줄로 뺀다.
        tk.Label(
            root, text="코드는 되돌릴 수 없게 변환(SHA-256)되어 중복 확인 용도로만 저장됩니다",
            font=("Arial", 8), fg="#666666",
        ).pack(pady=(2, 0))

        tk.Label(root, text="등록할 드롭스 코드를 한 줄에 하나씩 입력하세요 (중복/공백은 자동 정리):", font=("Arial", 10, "bold")).pack(pady=10)

        self.code_text = scrolledtext.ScrolledText(root, width=75, height=12)
        self.code_text.pack(pady=5)
        self.code_text.bind("<<Paste>>", self.on_paste_code)
        self.code_text.tag_configure("code_success", foreground="#2e7d32")
        self.code_text.tag_configure("code_fail", foreground="#C61717")

        # 기본 Tk 텍스트 위젯에는 우클릭 메뉴가 없어서 별도로 추가.
        # "붙여넣기"는 <<Paste>> 가상 이벤트를 발생시켜, Ctrl+V와 동일하게 자동 줄바꿈 로직을 그대로 탄다.
        self.code_menu = tk.Menu(self.code_text, tearoff=0)
        self.code_menu.add_command(label="잘라내기", command=lambda: self.code_text.event_generate("<<Cut>>"))
        self.code_menu.add_command(label="복사", command=lambda: self.code_text.event_generate("<<Copy>>"))
        self.code_menu.add_command(label="붙여넣기", command=lambda: self.code_text.event_generate("<<Paste>>"))
        self.code_menu.add_separator()
        self.code_menu.add_command(label="전체 선택", command=lambda: self.code_text.tag_add("sel", "1.0", "end"))

        def show_code_menu(event):
            self.code_menu.tk_popup(event.x_root, event.y_root)

        self.code_text.bind("<Button-3>", show_code_menu)

        # 확인 클릭 대기 중에 입력창의 코드가 전부 지워지면(수동 삭제) 등록을 포기한 것으로 보고
        # abandon_trigger를 세운다 — 아래 confirm_trigger 대기 루프에서 이 신호도 함께 감시한다.
        def on_code_text_modified(event):
            self.code_text.edit_modified(False)
            if not self.code_text.get("1.0", "end-1c").strip():
                self.abandon_trigger.set()

        self.code_text.bind("<<Modified>>", on_code_text_modified)

        self.start_btn = tk.Button(
            root, text="브라우저 열고 동시 등록 시작",
            command=self.start_redemption,
            width=30, height=2,
            bg="#C61717", fg="white", font=("Arial", 11, "bold")
        )
        self.start_btn.pack(pady=10)

        # 입력창의 코드를 그대로 다시 등록 시작 (session_active 상태면 launch()가 자동으로
        # 열려있는 브라우저를 재사용함 — v1.7.9 기능)
        self.reregister_btn = tk.Button(
            root, text="코드 재등록",
            command=self.start_redemption,
            width=30, height=2,
            bg="#7a1414", fg="white", font=("Arial", 11, "bold")
        )
        self.reregister_btn.pack(pady=(0, 10))

        # 한 배치 작업이 끝난 뒤에도 브라우저를 닫지 않고 대기 중이면 True — 이 상태에서
        # "시작"을 다시 누르면 새 브라우저를 띄우는 대신 열려있는 창들에 새 코드를 넣는다.
        self.session_active = False
        self.next_batch_queue = queue.Queue()

        # 앱 종료 시 백그라운드 스레드/브라우저를 정리하기 위한 참조들.
        self.async_loop = None       # 백그라운드 스레드가 돌리는 asyncio 이벤트 루프
        self.live_contexts = None    # 지금 열려있는 Playwright 브라우저 컨텍스트 리스트
        self.worker_thread = None    # 백그라운드 작업 스레드

        # 확인 화면(상품명/계정)이 뜬 뒤, 사용자가 직접 확인하고 눌러야 전체 탭에서 동시에 "확인"이 클릭됨
        self.confirm_trigger = threading.Event()
        # 확인 대기 중 브라우저가 전부 닫히거나 코드가 전부 지워지면 세워져서, 대기를 포기하고
        # 정상 종료 경로로 빠지게 만드는 신호.
        self.abandon_trigger = threading.Event()
        self.confirm_now_btn = tk.Button(
            root, text="지금 전체 확인 버튼 동시 클릭",
            command=self.trigger_confirm,
            width=30, height=2, state=tk.DISABLED,
            bg="#1D2951", fg="white", font=("Arial", 11, "bold")
        )
        self.confirm_now_btn.pack(pady=(0, 10))

        tk.Label(root, text="진행 상황 로그:", font=("Arial", 10, "bold")).pack(pady=5)
        
        self.log_text = scrolledtext.ScrolledText(root, width=75, height=15, state='disabled', bg="#f4f4f4")
        self.log_text.pack(pady=5)

        tk.Label(root, text=f"v{APP_VERSION}", font=("Arial", 8), fg="#999999").pack(side=tk.RIGHT, padx=10, pady=(0, 6))

        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

    def on_close(self):
        """앱을 닫을 때 열려있는 브라우저를 전부 정리해서 크롬 프로세스가 백그라운드에 orphan으로
        남지 않게 하고, 저장된 로그인 세션(쿠키 등)도 지워서 다음 실행 땐 항상 새로 로그인하게
        한다."""
        # 확인 버튼 대기 중이었다면 그 대기도 함께 풀어서 백그라운드 작업이 계속 걸려있지 않게 함.
        self.abandon_trigger.set()

        loop = self.async_loop
        contexts = self.live_contexts
        if loop is not None and contexts:
            async def close_all():
                await asyncio.gather(*(ctx.close() for ctx in list(contexts)), return_exceptions=True)
            try:
                future = asyncio.run_coroutine_threadsafe(close_all(), loop)
                future.result(timeout=10)
            except Exception:
                pass

        worker = self.worker_thread
        if worker is not None and worker.is_alive():
            # 브라우저가 다 닫혔으니 백그라운드 파이프라인이 스스로 마무리(Playwright 드라이버
            # 정리 포함)할 짧은 유예를 준다 — 못 끝내도 데몬 스레드라 프로세스 종료 시 정리됨.
            worker.join(timeout=5)

        try:
            profiles_dir = os.path.join(get_base_dir(), "browser_profiles")
            if os.path.isdir(profiles_dir):
                shutil.rmtree(profiles_dir, ignore_errors=True)
        except Exception:
            pass
        self.root.destroy()

    def trigger_confirm(self):
        """'지금 전체 확인 버튼 동시 클릭' 버튼 클릭 시 백그라운드 작업에 신호를 보냄."""
        self.confirm_now_btn.config(state=tk.DISABLED)
        self.confirm_trigger.set()

    def on_paste_code(self, event=None):
        """붙여넣기를 직접 처리 (클립보드 읽기 -> 삽입 -> 줄바꿈 -> 커서 이동)까지 한 번에 동기 처리.
        기본 Paste 동작에 맡기고 after_idle로 뒤처리하면 타이밍이 꼬여 중복/유실이 생겨서 직접 처리한다."""
        try:
            clip = self.code_text.clipboard_get()
        except tk.TclError:
            return "break"

        try:
            self.code_text.delete("sel.first", "sel.last")
        except tk.TclError:
            pass

        self.code_text.insert("insert", clip)
        idx = self.code_text.index("insert")
        # 버퍼 맨 끝에서 next_char를 읽으면 Tk가 실제로는 없는 가상의 줄바꿈을 돌려주므로,
        # 맨 끝인지 먼저 확인해야 "이미 줄바꿈 있음"으로 착각해 진짜 줄바꿈을 안 넣는 버그를 피한다.
        at_end = self.code_text.compare(idx, "==", "end-1c")
        next_char = "" if at_end else self.code_text.get(idx, f"{idx}+1c")
        if next_char != "\n":
            self.code_text.insert(idx, "\n")
        self.code_text.mark_set("insert", f"{idx}+1c")
        self.code_text.see("insert")
        return "break"

    def mark_code_result(self, code, status):
        """등록에 성공한 코드는 5초 카운트다운을 보여준 뒤 입력창에서 그 줄을 지우고, 실패한
        코드는 옆에 실패 표시만 남긴다 (스레드 안전)."""
        def update():
            is_success = status.startswith("성공")
            if is_success:
                self._countdown_delete(code, 5)
                return
            lines = self.code_text.get("1.0", "end-1c").split("\n")
            for i, line in enumerate(lines):
                base = line.split(self.MARKER_SEP)[0].rstrip()
                if base == code:
                    line_no = i + 1
                    marker_text = f"{code}{self.MARKER_SEP}실패 ({status})"
                    self.code_text.delete(f"{line_no}.0", f"{line_no}.end")
                    self.code_text.insert(f"{line_no}.0", marker_text)
                    self.code_text.tag_add("code_fail", f"{line_no}.0", f"{line_no}.end")
                    break
        self.root.after(0, update)

    def _countdown_delete(self, code, seconds_left):
        """성공한 코드 줄에 남은 초를 표시하고, 1초마다 갱신하다가 0초가 되면 그 줄을 지운다
        (Tk 메인스레드에서만 호출됨)."""
        lines = self.code_text.get("1.0", "end-1c").split("\n")
        for i, line in enumerate(lines):
            base = line.split(self.MARKER_SEP)[0].rstrip()
            if base == code:
                line_no = i + 1
                if seconds_left <= 0:
                    self.code_text.delete(f"{line_no}.0", f"{line_no + 1}.0")
                else:
                    marker_text = f"{code}{self.MARKER_SEP}성공 ({seconds_left}초 후 삭제...)"
                    self.code_text.delete(f"{line_no}.0", f"{line_no}.end")
                    self.code_text.insert(f"{line_no}.0", marker_text)
                    self.code_text.tag_add("code_success", f"{line_no}.0", f"{line_no}.end")
                    self.root.after(1000, lambda: self._countdown_delete(code, seconds_left - 1))
                break

    def log(self, message):
        """로그 창에 텍스트를 추가하고, 동시에 run_log.txt 파일에도 저장 (스레드 안전).
        문제가 생기면 이 파일 내용을 그대로 보내주면 됨 — 캡처/복사 없이 바로 분석 가능."""
        line = f"[{time.strftime('%H:%M:%S')}] {message}"

        def append():
            self.log_text.config(state='normal')
            self.log_text.insert(tk.END, line + "\n")
            self.log_text.see(tk.END)
            self.log_text.config(state='disabled')
        # 메인 GUI 스레드에서 UI 업데이트 보장
        self.root.after(0, append)

        try:
            with open(self.log_file_path, "a", encoding="utf-8") as f:
                f.write(line + "\n")
        except Exception:
            pass

    MARKER_SEP = "  → "

    def start_redemption(self):
        """시작 버튼 클릭 이벤트"""
        raw_text = self.code_text.get("1.0", tk.END)
        seen = set()
        codes = []
        for line in raw_text.split("\n"):
            # 이전 실행에서 붙은 "코드  → 성공/실패 (...)" 표시를 떼어내고 순수 코드만 추출
            code = line.split(self.MARKER_SEP)[0].strip()
            if code and code not in seen:
                seen.add(code)
                codes.append(code)

        if not codes:
            messagebox.showwarning("입력 오류", "코드를 최소 1개 이상 입력해주세요.")
            return

        codes = self.filter_already_registered(codes)
        if not codes:
            return

        self.launch(codes)

    def filter_already_registered(self, codes):
        """기록에 이미 있는 코드를 알려주고 제외할지 묻는다.

        기록은 어디까지나 참고용이다 — 등록에 성공했다고 기록됐어도 실제로는 실패했을 수
        있으므로(확인 버튼 클릭 여부만 보고 성공으로 판정한다, v1.9.0) 자동으로 빼버리지 않고
        판단을 사용자에게 넘긴다. 진행을 취소하면 빈 리스트를 반환한다.
        """
        if not self.dup_check_var.get():
            return codes

        salt, prints = load_registry(self.registry_path)
        dup = [c for c in codes if code_fingerprint(c, salt) in prints]
        if not dup:
            return codes

        remaining = [c for c in codes if c not in dup]
        detail = "\n".join(f"  · {mask_code(c)}" for c in dup[:10])
        if len(dup) > 10:
            detail += f"\n  · 외 {len(dup) - 10}개"

        if not remaining:
            messagebox.showwarning(
                "이미 등록한 코드",
                f"입력한 {len(codes)}개가 모두 이전에 등록한 기록이 있습니다.\n\n{detail}\n\n"
                "그래도 진행하시려면 '이미 등록한 코드 확인'을 끄고 다시 시도해주세요.",
            )
            return []

        answer = messagebox.askyesnocancel(
            "이미 등록한 코드",
            f"입력한 {len(codes)}개 중 {len(dup)}개는 이전에 등록한 기록이 있습니다.\n\n"
            f"{detail}\n\n"
            f"[예] 이 {len(dup)}개를 빼고 나머지 {len(remaining)}개만 진행\n"
            f"[아니오] {len(codes)}개 전부 그대로 진행\n"
            f"[취소] 진행하지 않음",
        )
        if answer is None:
            return []
        if answer:
            self.log(f"[알림] 이미 등록한 기록이 있는 코드 {len(dup)}개를 제외했습니다.")
            return remaining
        return codes

    def launch(self, codes):
        """탭 개수 확인 후 백그라운드에서 등록 작업을 시작."""
        if len(codes) > 8:
            if not messagebox.askyesno("확인", f"브라우저 탭을 {len(codes)}개 엽니다. 계속할까요?"):
                return

        if self.session_active:
            # 이전 배치가 끝난 뒤 브라우저를 열어둔 채 대기 중 — 새로 띄우지 않고
            # 지금 열려있는 창들에 이 코드들을 넣어서 그대로 재사용한다.
            self.log(f"\n[알림] 열려있는 브라우저에 새 코드 {len(codes)}개를 등록합니다...")
            self.next_batch_queue.put(codes)
            return

        self.start_btn.config(state=tk.DISABLED)
        self.reregister_btn.config(state=tk.DISABLED)
        self.confirm_now_btn.config(state=tk.DISABLED)
        self.confirm_trigger.clear()

        # 실행할 때마다 로그 파일을 새로 시작 (항상 가장 최근 실행 기록만 남도록)
        try:
            with open(self.log_file_path, "w", encoding="utf-8") as f:
                f.write(f"=== 실행 시작 {time.strftime('%Y-%m-%d %H:%M:%S')} (v{APP_VERSION}) ===\n")
        except Exception:
            pass

        self.log(f"총 {len(codes)}개의 코드를 인식했습니다.")
        self.log("백그라운드 스레드에서 브라우저를 구동합니다...")

        # 자동 로그인 정보는 어디에도 저장하지 않고, 이번 실행에만 메모리로 전달한다.
        # 입력창은 바로 비워서 화면에도 남지 않게 한다.
        login_email = self.login_email_entry.get().strip()
        login_password = self.login_password_entry.get()
        self.login_password_entry.delete(0, tk.END)
        self.login_password_entry.config(show="*")  # 혹시 버튼을 누른 채로 시작했을 경우 대비

        login_stagger = self.read_login_stagger()

        # Playwright 비동기 이벤트 루프를 별도의 스레드에서 실행 (GUI 멈춤 방지)
        self.worker_thread = threading.Thread(
            target=self.run_async_worker,
            args=(codes, login_email, login_password, login_stagger),
            daemon=True,
        )
        self.worker_thread.start()

    def read_login_stagger(self):
        """GUI에 입력된 창별 로그인 간격을 초 단위 실수로 읽는다.
        숫자가 아니거나 범위를 벗어나면 조용히 넘어가지 않고 로그로 알린 뒤 기본값/경계값으로
        보정한다 — 오타 때문에 의도와 다른 간격으로 돌아가면 2FA 승인이 꼬이기 때문."""
        raw = self.login_stagger_var.get().strip()
        try:
            value = float(raw)
        except ValueError:
            self.log(
                f"[경고] 로그인 간격 '{raw}'을(를) 숫자로 읽을 수 없어 "
                f"기본값 {DEFAULT_LOGIN_STAGGER_SECONDS}초로 진행합니다."
            )
            value = float(DEFAULT_LOGIN_STAGGER_SECONDS)

        clamped = min(max(value, MIN_LOGIN_STAGGER_SECONDS), MAX_LOGIN_STAGGER_SECONDS)
        if clamped != value:
            self.log(
                f"[경고] 로그인 간격은 {MIN_LOGIN_STAGGER_SECONDS}~{MAX_LOGIN_STAGGER_SECONDS}초 "
                f"범위만 쓸 수 있어 {clamped:g}초로 조정했습니다."
            )
        # 보정된 값을 입력칸에도 되돌려 써서, 화면에 보이는 값과 실제 동작이 어긋나지 않게 한다.
        self.login_stagger_var.set(f"{clamped:g}")
        return clamped

    def run_async_worker(self, codes, login_email, login_password, login_stagger):
        """비동기 이벤트 루프 래퍼. asyncio.run() 대신 루프를 직접 관리해서, 앱 종료 시
        self.async_loop을 통해 이 루프에 "브라우저 전부 닫기"를 즉시 예약할 수 있게 한다."""
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        self.async_loop = loop
        try:
            loop.run_until_complete(
                self.async_playwright_logic(codes, login_email, login_password, login_stagger)
            )
        finally:
            loop.close()
            self.async_loop = None
        # 작업 완료 후 버튼 활성화
        self.root.after(0, lambda: self.start_btn.config(state=tk.NORMAL))
        self.root.after(0, lambda: self.reregister_btn.config(state=tk.NORMAL))

    async def async_playwright_logic(self, codes, login_email="", login_password="",
                                     login_stagger=DEFAULT_LOGIN_STAGGER_SECONDS):
        """실제 Playwright 제어 로직 (비동기)"""
        base_dir = get_base_dir()
        redeem_url = "https://kr.checkout.battle.net/shop/ko/checkout/key-claim"
        
        self.log("[알림] 브라우저 세션을 불러옵니다...")

        # 코드마다 완전히 별도의 브라우저 프로필(독립 세션/쿠키)을 쓴다. 한 프로필의 탭 여러 개로
        # 하면 서버 입장에서 "한 세션이 동시에 여러 건을 처리하려 한다"로 보여 리디렉션 초과 등
        # 문제가 반복됐음 — 사용자가 실제로 여러 브라우저를 따로 열어 성공한 경험과 일치한다.
        contexts = []
        self.live_contexts = contexts  # 앱 종료 시(on_close) 이 리스트를 보고 전부 닫는다
        try:
            async with async_playwright() as p:
                pages = []
                # 창마다 닫힘 이벤트를 등록해두면, 나중에 "브라우저가 전부 닫혔는지"를 언제든
                # ev.is_set()으로 논블로킹 확인할 수 있다 (확인 대기 중 중단 감지, 배치 종료 후
                # 재사용 대기 등 여러 곳에서 재사용).
                close_events = []

                # 필요한 창 개수(target_count)까지 부족한 만큼만 새로 띄운다. 이미 열려있는
                # 창(재사용 배치)은 건드리지 않고, 처음 실행이거나 이전보다 코드가 많아졌을 때만
                # 그 차이만큼 추가로 연다.
                async def ensure_pages(target_count):
                    start_idx = len(pages)
                    # 창 크기와 좌표를 화면 해상도에서 역산한다(v1.9.20). 이미 열려있는 창은
                    # 다시 배치하지 않으므로, 새로 여는 창에만 이 좌표를 적용한다.
                    win_w, win_h, positions = compute_window_layout(
                        target_count, self.screen_w, self.screen_h
                    )
                    if start_idx == 0 and target_count:
                        self.log(
                            f"[알림] 화면 {self.screen_w}x{self.screen_h}에 맞춰 창 {target_count}개를 "
                            f"{win_w}x{win_h} 크기로 배치합니다."
                        )
                    for i in range(start_idx, target_count):
                        pos_x, pos_y = positions[i]
                        ctx = await p.chromium.launch_persistent_context(
                            # 프로필들은 기능상 분리되어야 하지만(리디렉션 버그 방지), 실행
                            # 폴더에 여러 개가 흩어져 지저분해 보이지 않도록 상위 폴더 하나로
                            # 모아둔다.
                            user_data_dir=os.path.join(base_dir, "browser_profiles", f"slot_{i + 1}"),
                            # 번들 크로미움(약 430MB) 대신 PC에 이미 설치된 구글 크롬을 그대로
                            # 사용 — exe 용량을 크게 줄임. 대상 PC에 크롬이 설치돼 있어야 함.
                            channel="chrome",
                            headless=False,
                            viewport={"width": win_w, "height": win_h},
                            args=[
                                "--disable-blink-features=AutomationControlled",
                                f"--window-position={pos_x},{pos_y}",
                                f"--window-size={win_w},{win_h}",
                            ]
                        )
                        contexts.append(ctx)
                        ev = asyncio.Event()
                        ctx.on("close", lambda ev=ev: ev.set())
                        close_events.append(ev)
                        page_obj = ctx.pages[0] if ctx.pages else await ctx.new_page()
                        pages.append(page_obj)
                    return [(i, pages[i]) for i in range(start_idx, target_count)]

                new_pages = await ensure_pages(len(codes))

                self.log(f"[알림] 총 {len(pages)}개의 독립된 브라우저 창이 준비되었습니다. 코드 등록 페이지로 이동합니다.")

                # 블리자드 리딤 코드 인풋 셀렉터
                selector = "input#code, input[name='code'], input[name='claimCode'], input[id='claim-code'], #claim-code, input[placeholder='코드 입력']"

                # 기본값(wait_until="load")은 이미지/폰트 등 모든 리소스가 끝날 때까지 기다리는데,
                # 탭 여러 개가 동시에 요청하면 그중 일부가 30초 타임아웃으로 완전히 실패하는 걸
                # 실측으로 확인함. HTML 파싱 완료 시점(domcontentloaded)까지만 기다리면 해결됨.
                # 탭 하나가 연결 오류("페이지가 작동하지 않습니다" 등)를 일으켜도 그 예외가
                # gather() 전체를 터뜨려서 멀쩡한 다른 탭까지 같이 끌고 죽지 않도록,
                # 탭별로 개별 처리하고 실패한 탭만 재시도한다.
                # v1.6.0부터 코드마다 독립된 브라우저 프로필(세션)을 쓰므로, 예전에 리디렉션
                # 초과를 유발했던 "세션 공유로 인한 경합"이 발생하지 않아 시차 없이 완전 동시로
                # 이동한다 (독립 컨텍스트 10개 동시 이동은 이미 0/10 실패로 실측 검증됨).
                async def safe_goto(page, idx, retries=2):
                    for attempt in range(retries + 1):
                        try:
                            await page.goto(redeem_url, wait_until="domcontentloaded")
                            return True
                        except Exception as e:
                            if attempt < retries:
                                await asyncio.sleep(1)
                            else:
                                self.log(f" -> 탭 {idx+1}: 페이지 이동 실패 ({scrub_codes(e, codes)})")
                                return False

                # 자동 로그인(선택) — 이메일 입력 후 "계속" → 비밀번호 입력 후 로그인의 2단계
                # 폼을 자동으로 채운다. 이 정보는 어디에도 저장되지 않고 이번 실행 메모리에서만
                # 쓰인다. 2FA/캡차 등으로 중간에 막히면 그냥 실패로 남기고, 아래의 "코드 입력란이
                # 보일 때까지 대기"가 그대로 안전망 역할을 한다(수동으로 마저 진행하면 됨).
                # 창을 한꺼번에 자동 로그인시키면, 배틀넷 인증기 앱 승인처럼 폰을 직접 들어서
                # 눌러야 하는 2FA가 여러 창에서 동시에 뜰 때 처리할 시간이 부족하다 — 창마다
                # 승인할 시간을 벌 수 있도록 간격을 둔다. 필요한 시간은 사람마다/상황마다
                # 다르므로 v1.9.17부터 GUI 입력값을 그대로 쓴다(기본 5초, 0이면 전부 동시).
                login_stagger_seconds = login_stagger

                async def auto_login(page, idx):
                    if not login_email or not login_password:
                        return
                    await asyncio.sleep(idx * login_stagger_seconds)
                    try:
                        email_selector = "input[type='email'], input[name='accountName'], input#accountName"
                        await page.locator(email_selector).first.fill(login_email, timeout=5000)
                        await page.locator("button[type='submit']").first.click()
                        password_selector = "input[type='password'], input[name='password'], input#password"
                        await page.locator(password_selector).first.wait_for(timeout=10000)
                        await page.locator(password_selector).first.fill(login_password)
                        await page.locator("button[type='submit']").first.click()
                        self.log(f" -> 창 {idx+1}: 자동 로그인 시도 완료.")
                    except Exception:
                        self.log(f" -> 창 {idx+1}: 자동 로그인 폼을 못 찾음 — 수동으로 로그인해주세요.")

                # 창마다 세션이 독립적이라, 이전처럼 "아무 한 곳만 로그인하면 전체 적용"이 아니라
                # 창마다 각각 로그인 완료(코드 입력란 등장)를 기다려야 한다. 이미 로그인이 저장된
                # 창은 즉시 통과되고, 새 창만 사용자가 로그인할 때까지 기다린다.
                # 탭 하나가 도중에 닫히거나 오류가 나도 그 예외가 gather() 전체를 터뜨려서
                # 멀쩡한 다른 창들까지 같이 끌고 죽지 않도록(실제로 이 문제로 5개 창이 전부
                # 닫힌 적이 있었음) 창별로 개별 처리한다.
                async def wait_login(page, idx):
                    try:
                        await page.wait_for_selector(selector, timeout=0)
                        return True
                    except Exception as e:
                        self.log(f" -> 창 {idx+1}: 로그인 대기 중 창이 닫히거나 오류 발생 ({scrub_codes(e, codes)})")
                        return False

                async def setup_pages(indexed_pages):
                    """새로 연 탭들만 페이지 이동 + 자동 로그인 + 로그인 대기까지 처리한다
                    (이미 로그인된 채로 재사용 중인 탭은 다시 건드리지 않는다)."""
                    if not indexed_pages:
                        return
                    goto_results = await asyncio.gather(*(safe_goto(page, idx) for idx, page in indexed_pages))
                    if not all(goto_results):
                        self.log("[경고] 일부 탭이 페이지 이동에 실패했습니다. 나머지 탭으로 계속 진행합니다.")

                    if login_email and login_password:
                        self.log(
                            f"[알림] 자동 로그인을 시도합니다 (저장되지 않음, 이번 실행에서만 사용). "
                            f"창별 간격 {login_stagger_seconds:g}초..."
                        )
                        await asyncio.gather(*(auto_login(page, idx) for idx, page in indexed_pages))

                    self.log("\n========================================================")
                    self.log(" [주의] 자동 로그인이 안 된 창은 직접 로그인해주세요 (세션이 분리되어 있어 창마다 필요).")
                    self.log(" (이미 로그인된 적 있는 창은 자동으로 통과되어 대기하지 않습니다.)")
                    self.log(" 2FA(문자 인증) 및 캡차가 있다면, 그 창에서 직접 완료해주세요.")
                    self.log(" 완료 후 '코드 입력' 란이 보일 때까지 대기합니다.")
                    self.log("========================================================\n")

                    login_wait_results = await asyncio.gather(*(wait_login(page, idx) for idx, page in indexed_pages))
                    if not all(login_wait_results):
                        self.log("[경고] 일부 창에서 로그인을 완료하지 못했습니다. 나머지 창으로 계속 진행합니다.")
                    await asyncio.sleep(2)  # 리다이렉션 및 렌더링 안정화 대기

                await setup_pages(new_pages)

                self.log("[알림] 모든 창의 로그인 확인 완료. 각 탭에 코드를 장전합니다...")

                submit_selector = "button[type='submit'], button:has-text('코드 등록'), button:has-text('Redeem Code'), #submit-claim-code"
                confirm_selector = "button:has-text('확인')"

                # 배치 하나(코드 장전 → 등록 → 확인 → 결과)를 전부 처리한 뒤, 브라우저를 닫지
                # 않고 새 배치(코드)가 들어오길 기다렸다가 같은 창들로 계속 반복한다.
                while True:
                    # 각 탭에 코드를 입력하고 대기하는 서브 함수
                    another_code_selector = "button:has-text('다른 코드 등록'), a:has-text('다른 코드 등록')"

                    async def prepare_page(page, code, idx):
                        try:
                            # 이미 로그인된 탭(코드 입력란이 이미 보이는 탭)은 새로고침할 필요가 없다.
                            # 무조건 새로고침하면 이미 준비된 탭까지 불필요하게 깜박이게 된다.
                            # goto()도 이 try 안에서 처리해서, 연결 오류가 나도 이 탭만 실패로
                            # 처리되고 다른 탭들의 장전이 통째로 죽지 않게 한다.
                            already_ready = await page.locator(selector).count() > 0
                            if not already_ready:
                                # 직전 배치가 성공해서 "코드가 등록되었습니다" 화면에 있는 탭이라면,
                                # 사이트가 제공하는 "다른 코드 등록" 버튼으로 이동한다 — 전체 페이지
                                # 재이동(goto)은 예전에 리디렉션 초과 버그의 원인이었던 적이 있어,
                                # 사이트 자체 내비게이션이 있을 땐 그쪽을 우선한다.
                                another_code_btn = page.locator(another_code_selector)
                                if await another_code_btn.count() > 0:
                                    await another_code_btn.first.click()
                                    try:
                                        await page.wait_for_selector(selector, timeout=10000)
                                    except Exception:
                                        await page.goto(redeem_url, wait_until="domcontentloaded")
                                else:
                                    await page.goto(redeem_url, wait_until="domcontentloaded")
                            await page.wait_for_selector(selector, timeout=15000)
                            input_locator = page.locator(selector).first
                            await input_locator.fill(code)
                            self.log(f" -> 탭 {idx+1}: {mask_code(code)} 장전 완료.")
                            return True
                        except Exception as e:
                            self.log(f" -> 탭 {idx+1}: 장전 실패 ({scrub_codes(e, [code])})")
                            return False

                    # v1.6.0부터 코드마다 독립된 브라우저 프로필(세션)을 쓰므로, 코드 장전(재이동+
                    # 입력)도 시차 없이 전체 탭 동시 처리로 되돌린다.
                    prep_results = await asyncio.gather(
                        *(prepare_page(pages[i], codes[i], i) for i in range(len(codes)))
                    )

                    if not all(prep_results):
                        self.log("[경고] 일부 탭에서 코드 장전에 실패했습니다. 계속 진행합니다.")

                    self.log("\n[알림] 모든 탭 장전 완료. 전체 탭에서 동시에 등록 버튼을 누릅니다.")

                    # v1.6.0부터 코드마다 완전히 독립된 브라우저 프로필(세션)을 쓰므로, 이전에
                    # 리디렉션 초과를 유발했던 "한 세션이 동시에 여러 건을 처리" 상황 자체가
                    # 발생하지 않는다 — 그래서 시차 없이 완전 동시 클릭으로 되돌린다.
                    async def submit_then_wait(page, idx):
                        try:
                            await page.locator(submit_selector).first.click()
                        except Exception as e:
                            self.log(f" -> 탭 {idx+1}: 등록 버튼 클릭 실패 ({scrub_codes(e, codes)})")
                            return False
                        try:
                            await page.locator(confirm_selector).first.wait_for(timeout=60000)
                            self.log(f" -> 탭 {idx+1}: 등록 클릭 완료, 확인 화면 도달.")
                            return True
                        except Exception:
                            self.log(f" -> 탭 {idx+1}: 확인 화면 대기 시간 초과.")
                            return False

                    confirm_ready = await asyncio.gather(
                        *(submit_then_wait(pages[i], i) for i in range(len(codes)))
                    )

                    if not all(confirm_ready):
                        self.log("[경고] 일부 탭에서 확인 화면 로딩이 늦어지고 있습니다. 브라우저 창을 직접 확인해주세요.")

                    self.log("\n========================================================")
                    self.log(" [주의] 각 탭의 확인 화면(상품명/계정)을 직접 확인해주세요.")
                    self.log(" 이상 없으면 '지금 전체 확인 버튼 동시 클릭'을 눌러주세요.")
                    self.log(" 그 순간 모든 탭에서 '확인'이 동시에 클릭되며 등록이 확정됩니다.")
                    self.log("========================================================\n")

                    self.confirm_trigger.clear()
                    self.abandon_trigger.clear()
                    self.root.after(0, lambda: self.confirm_now_btn.config(state=tk.NORMAL))

                    # 사용자가 버튼을 누를 때까지 대기하되, 그 사이 브라우저가 전부 닫히거나
                    # 입력창의 코드가 전부 지워지면(=사용자가 포기한 것으로 판단) 무한 대기에
                    # 빠지지 않고 빠져나온다 — 예전엔 아무 신호가 없어서 "시작"/"코드 재등록"
                    # 버튼이 영원히 잠긴 채로 남는 문제가 있었음.
                    abandoned = False
                    while not self.confirm_trigger.is_set():
                        if self.abandon_trigger.is_set() or (close_events and all(ev.is_set() for ev in close_events)):
                            abandoned = True
                            break
                        await asyncio.sleep(0.3)

                    self.root.after(0, lambda: self.confirm_now_btn.config(state=tk.DISABLED))

                    if abandoned:
                        self.log("[알림] 브라우저가 모두 닫히거나 코드가 모두 지워져 이번 등록을 중단합니다.")
                        click_results = [False] * len(codes)
                    else:
                        self.log("[알림] 최종 확인 버튼 동시 클릭 중 (여기서 실제로 등록이 완료됩니다)...")

                        # 2단계: 확인 화면의 "확인" 버튼 동시 클릭 (실제 등록 확정)
                        # 코드를 정상적으로 입력했다면 등록되는 게 당연한 결과이므로, 클릭 이후
                        # 결과 화면을 읽어서 성공/실패를 검증하거나 재시도하지 않는다 — 클릭 자체가
                        # 됐는지만 확인한다. (예전엔 결과 화면 텍스트를 읽어 판정했는데, 렌더링
                        # 타이밍에 따라 빈 화면으로 잘못 읽혀 이미 성공한 코드를 또 제출하는
                        # 부작용이 있었음 — 애초에 검증 자체를 없애서 그 문제도 함께 제거)
                        async def click_confirm(page, idx):
                            try:
                                # Playwright의 click()은 실제 클릭 전에 "요소가 눌러도 되는 상태인지"
                                # 확인하는 절차를 거치는데, 이 확인에 걸리는 시간이 탭마다 미세하게 달라서
                                # asyncio.gather로 동시에 시작해도 실제 클릭 순간이 탭마다 어긋날 수 있다.
                                # 먼저 버튼이 준비됐는지만 확인해두고, 실제 클릭은 순수 JS로 즉시 실행해서
                                # 탭 간 클릭 타이밍 차이를 최소화한다.
                                await page.locator(confirm_selector).first.wait_for(state="visible", timeout=60000)
                                clicked = await page.evaluate(
                                    """() => {
                                        const btn = Array.from(document.querySelectorAll('button'))
                                            .find(b => (b.textContent || '').includes('확인'));
                                        if (btn) { btn.click(); return true; }
                                        return false;
                                    }"""
                                )
                                if not clicked:
                                    raise Exception("확인 버튼을 JS로 찾지 못함")
                                return True
                            except Exception as e:
                                self.log(f" -> 탭 {idx+1}: 확인 버튼 클릭 실패 ({scrub_codes(e, codes)})")
                                return False

                        click_results = await asyncio.gather(
                            *(click_confirm(pages[i], i) for i in range(len(codes)))
                        )

                        self.log("\n[알림] 전체 탭에서 등록 확인 클릭을 완료했습니다.")

                    succeeded = []
                    for i, code in enumerate(codes):
                        if abandoned:
                            status = "취소됨 (브라우저 종료 또는 코드 삭제로 등록 중단)"
                        else:
                            status = "성공 (등록 완료)" if click_results[i] else "실패 (확인 버튼 클릭 안 됨 — 브라우저에서 직접 확인해주세요)"
                            if click_results[i]:
                                succeeded.append(code)
                        self.log(f" [{i+1}번 {mask_code(code)}] -> {status}")
                        self.mark_code_result(code, status)

                    # 중복 등록 방지 기록 — 코드 원본이 아니라 되돌릴 수 없는 지문만 덧붙인다.
                    # (v1.9.19부터 코드 전체를 담던 results.csv를 이 방식으로 대체했다.)
                    if succeeded and self.dup_check_var.get():
                        salt, prints = load_registry(self.registry_path)
                        fresh = {code_fingerprint(c, salt) for c in succeeded} - prints
                        append_registry(self.registry_path, salt, fresh)
                        if fresh:
                            self.log(f"[알림] 등록 성공한 {len(fresh)}개를 중복 확인 기록에 추가했습니다.")

                    self.log("작업이 모두 끝났습니다. 각 탭에서 결과를 직접 확인해주세요.")
                    self.log("브라우저 창은 계속 열어둡니다 — 새 코드를 입력하고 '코드 재등록'을 누르면")
                    self.log("이 창들을 그대로 재사용합니다. 완전히 끝내려면 창을 모두 직접 닫아주세요.")

                    self.session_active = True
                    self.root.after(0, lambda: self.start_btn.config(state=tk.NORMAL))
                    self.root.after(0, lambda: self.reregister_btn.config(state=tk.NORMAL))

                    # 브라우저가 전부 닫히거나, 새 배치(코드)가 들어오거나 — 둘 중 먼저 오는 걸
                    # 기다린다. 큐를 블로킹으로 기다리면 브라우저가 먼저 닫혔을 때 백그라운드
                    # 스레드가 계속 남으므로, non-blocking 폴링으로 둘 다 확인한다. close_events는
                    # ensure_pages()에서 창이 열릴 때마다 갱신되는 것을 그대로 재사용한다.
                    next_codes = None
                    while True:
                        if any(ev.is_set() for ev in close_events):
                            break
                        try:
                            next_codes = self.next_batch_queue.get_nowait()
                            break
                        except queue.Empty:
                            pass
                        await asyncio.sleep(0.5)

                    self.session_active = False
                    self.root.after(0, lambda: self.start_btn.config(state=tk.DISABLED))
                    self.root.after(0, lambda: self.reregister_btn.config(state=tk.DISABLED))

                    if next_codes is None:
                        break

                    codes = next_codes
                    added_pages = await ensure_pages(len(codes))
                    if added_pages:
                        self.log(f"[알림] 추가로 {len(added_pages)}개의 창을 새로 엽니다...")
                        await setup_pages(added_pages)
                    self.log(f"\n[알림] 새 배치({len(codes)}개) 코드 장전을 시작합니다...")
                    # while True 맨 위로 돌아가 같은 창들로 다음 배치를 처리한다

        except Exception as e:
            self.session_active = False
            self.log(f"[치명적 오류] 브라우저 제어 중 예외 발생: {scrub_codes(e, codes)}")
            # 여기서 브라우저들을 닫아두지 않으면, 창은 열린 채로 시작 버튼만 풀려서
            # 사용자가 다시 시작을 누르면 같은 프로필로 브라우저를 중복 실행하게 되고,
            # 크롬이 그걸 "재시작되는 것처럼" 보이는 방식으로 처리해버린다.
            if contexts:
                try:
                    await asyncio.gather(*(ctx.close() for ctx in contexts), return_exceptions=True)
                    self.log("[알림] 오류로 인해 브라우저를 정리했습니다. 다시 시작해주세요.")
                except Exception:
                    self.log("[경고] 브라우저 정리에도 실패했습니다. 프로그램을 완전히 종료 후 다시 실행해주세요.")

if __name__ == "__main__":
    # Windows 기본 정책(ProactorEventLoop)이어야 Playwright의 서브프로세스 구동이 동작함.
    # SelectorEventLoop로 바꾸면 NotImplementedError로 브라우저 실행 자체가 실패한다.
    root = tk.Tk()
    app = EzDropsApp(root)
    root.mainloop()
