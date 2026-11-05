"""The pre-authentication screen of an RDP server (the ``rdp_shot`` kind), captured as ``cveFeed.rdp_shot.capture`` does on the server.

``aardwolf`` (a headless RDP client) connects with the "none" method, which sends no credentials at all; a server that insists on Network Level
Authentication sends no frame and nothing is captured. The PNG goes back to the server, which decides whether it is a real frame and has it read:
nothing here looks at what the screen shows.
"""
import asyncio
import concurrent.futures
import io

CONNECT_TIMEOUT = 8      # seconds to complete the RDP security and MCS handshake
SCREEN_WAIT = 5          # seconds to let the server paint its pre-authentication screen once connected
CAP_GRACE = 15           # seconds past connect and paint that the whole capture may take before it is abandoned
VIDEO_WIDTH, VIDEO_HEIGHT = 1024, 768
MAX_IMAGE_BYTES = 4 * 1024 * 1024  # cveFeed.rdp_shot.MAX_IMAGE_BYTES: the server refuses a larger capture


def available():
    try:
        import aardwolf  # noqa: F401
    except ImportError:
        return False
    return True


async def _capture_async(host, port, wait, connect_timeout):
    from aardwolf.commons.factory import RDPConnectionFactory
    from aardwolf.commons.iosettings import RDPIOSettings
    from aardwolf.commons.queuedata.constants import VIDEO_FORMAT

    io_settings = RDPIOSettings()
    io_settings.video_width, io_settings.video_height = VIDEO_WIDTH, VIDEO_HEIGHT
    io_settings.video_bpp_min, io_settings.video_bpp_max = 15, 32
    io_settings.video_out_format = VIDEO_FORMAT.PNG
    io_settings.clipboard_use_pyperclip = False
    host_part = f'[{host}]' if ':' in host else host
    factory = RDPConnectionFactory.from_url(f'rdp+none://{host_part}:{port}', io_settings)  # "none": no credentials at all
    connection = factory.get_connection(io_settings)
    try:
        _, err = await asyncio.wait_for(connection.connect(), connect_timeout)
        if err is not None:
            raise err
        await asyncio.sleep(wait)
        if not connection.desktop_buffer_has_data:
            return None
        image = connection.get_desktop_buffer(VIDEO_FORMAT.PIL)
        buf = io.BytesIO()
        image.save(buf, 'PNG')
        return buf.getvalue()
    finally:
        try:
            await connection.terminate()
        except Exception:  # noqa: BLE001 - teardown must never mask or replace a real capture
            pass


def capture(host, port, connect_timeout=CONNECT_TIMEOUT, wait=SCREEN_WAIT):
    """PNG bytes of the pre-authentication screen, or ``None`` when nothing was painted within the wait. Raises on a connection or protocol error.
    Runs its own event loop on a dedicated thread with a hard wall-clock cap on top of the connect and paint timeouts."""
    limit = connect_timeout + wait + CAP_GRACE
    pool = concurrent.futures.ThreadPoolExecutor(max_workers=1)
    try:
        return pool.submit(lambda: asyncio.run(asyncio.wait_for(_capture_async(host, port, wait, connect_timeout), limit))).result(timeout=limit)
    finally:
        pool.shutdown(wait=False, cancel_futures=True)
