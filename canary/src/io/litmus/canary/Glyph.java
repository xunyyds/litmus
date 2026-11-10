package io.litmus.canary;

import android.graphics.Canvas;
import android.graphics.ColorFilter;
import android.graphics.Paint;
import android.graphics.Path;
import android.graphics.PixelFormat;
import android.graphics.Rect;
import android.graphics.RectF;
import android.graphics.drawable.Drawable;

/**
 * 极简矢量图标（refresh / ⋮ / 复制 / 导出 / 分享 / 搜索）。
 *
 * <p>为什么不放 png/svg：这个工程没有 gradle，{@code res/} 里的图片要么手写 xml vector
 * （aapt2 对属性名很挑），要么塞二进制资源；直接在 Canvas 上画既省事又不增体积，
 * 也顺手满足「零第三方依赖」。
 */
final class Glyph extends Drawable {

    static final int REFRESH = 0;
    static final int MORE = 1;
    static final int COPY = 2;
    static final int EXPORT = 3;
    static final int SHARE = 4;
    static final int SEARCH = 5;

    private final int kind;
    private final Paint paint = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final Path path = new Path();
    private final RectF rect = new RectF();

    private Glyph(int kind, int color) {
        this.kind = kind;
        paint.setColor(color);
        paint.setStyle(Paint.Style.STROKE);
        paint.setStrokeCap(Paint.Cap.ROUND);
        paint.setStrokeJoin(Paint.Join.ROUND);
    }

    static Glyph of(int kind, int color) {
        return new Glyph(kind, color);
    }

    @Override
    public void draw(Canvas canvas) {
        Rect b = getBounds();
        float w = b.width();
        float h = b.height();
        float cx = b.exactCenterX();
        float cy = b.exactCenterY();
        float size = Math.min(w, h);
        float stroke = Math.max(1.4f, size * 0.085f);
        paint.setStrokeWidth(stroke);
        paint.setStyle(Paint.Style.STROKE);

        switch (kind) {
            case REFRESH: {
                float r = size * 0.34f;
                rect.set(cx - r, cy - r, cx + r, cy + r);
                canvas.drawArc(rect, 145f, 288f, false, paint);
                paint.setStyle(Paint.Style.FILL);
                float a = (float) Math.toRadians(145f);
                float ax = (float) (cx + r * Math.cos(a));
                float ay = (float) (cy + r * Math.sin(a));
                float s = size * 0.17f;
                path.reset();
                path.moveTo(ax - s * 0.15f, ay - s);
                path.lineTo(ax + s * 0.85f, ay - s * 0.1f);
                path.lineTo(ax - s * 0.55f, ay + s * 0.45f);
                path.close();
                canvas.drawPath(path, paint);
                break;
            }
            case MORE: {
                // 竖排三点：⋮
                paint.setStyle(Paint.Style.FILL);
                float r = Math.max(1.6f, size * 0.062f);
                float gap = size * 0.24f;
                canvas.drawCircle(cx, cy - gap, r, paint);
                canvas.drawCircle(cx, cy, r, paint);
                canvas.drawCircle(cx, cy + gap, r, paint);
                break;
            }
            case COPY: {
                float s = size * 0.52f;
                float x = cx - s * 0.62f;
                float y = cy - s * 0.62f;
                float rr = s * 0.22f;
                canvas.drawRoundRect(new RectF(x, y, x + s, y + s), rr, rr, paint);
                float o = s * 0.30f;
                canvas.drawRoundRect(new RectF(x + o, y + o, x + o + s, y + o + s), rr, rr, paint);
                break;
            }
            case EXPORT: {
                float s = size * 0.34f;
                canvas.drawLine(cx, cy - s, cx, cy + s * 0.52f, paint);
                paint.setStyle(Paint.Style.FILL);
                path.reset();
                path.moveTo(cx - s * 0.5f, cy + s * 0.2f);
                path.lineTo(cx + s * 0.5f, cy + s * 0.2f);
                path.lineTo(cx, cy + s * 0.8f);
                path.close();
                canvas.drawPath(path, paint);
                paint.setStyle(Paint.Style.STROKE);
                float t = size * 0.38f;
                path.reset();
                path.moveTo(cx - t, cy + t * 0.78f);
                path.lineTo(cx - t, cy + t * 1.05f);
                path.quadTo(cx - t, cy + t * 1.18f, cx - t * 0.86f, cy + t * 1.18f);
                path.lineTo(cx + t * 0.86f, cy + t * 1.18f);
                path.quadTo(cx + t, cy + t * 1.18f, cx + t, cy + t * 1.05f);
                path.lineTo(cx + t, cy + t * 0.78f);
                canvas.drawPath(path, paint);
                break;
            }
            case SHARE: {
                // 三个节点 + 两条连线（经典的「分享」形状）
                paint.setStyle(Paint.Style.FILL);
                float r = Math.max(2f, size * 0.075f);
                float ax = cx - size * 0.24f;
                float ay = cy;
                float bx = cx + size * 0.24f;
                float by = cy - size * 0.24f;
                float ccx = cx + size * 0.24f;
                float ccy = cy + size * 0.24f;
                paint.setStyle(Paint.Style.STROKE);
                paint.setStrokeWidth(stroke * 0.85f);
                canvas.drawLine(ax, ay, bx, by, paint);
                canvas.drawLine(ax, ay, ccx, ccy, paint);
                paint.setStyle(Paint.Style.FILL);
                canvas.drawCircle(ax, ay, r, paint);
                canvas.drawCircle(bx, by, r, paint);
                canvas.drawCircle(ccx, ccy, r, paint);
                break;
            }
            case SEARCH:
            default: {
                float r = size * 0.28f;
                rect.set(cx - r - size * 0.06f, cy - r - size * 0.06f,
                        cx + r - size * 0.06f, cy + r - size * 0.06f);
                canvas.drawArc(rect, 0f, 360f, false, paint);
                canvas.drawLine(cx + r * 0.62f, cy + r * 0.62f,
                        cx + r * 1.25f, cy + r * 1.25f, paint);
                break;
            }
        }
    }

    @Override
    public void setAlpha(int alpha) {
        paint.setAlpha(alpha);
        invalidateSelf();
    }

    @Override
    public void setColorFilter(ColorFilter colorFilter) {
        paint.setColorFilter(colorFilter);
        invalidateSelf();
    }

    @Override
    public int getOpacity() {
        return PixelFormat.TRANSLUCENT;
    }
}
