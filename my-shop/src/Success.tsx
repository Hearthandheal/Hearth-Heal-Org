import { Link } from "react-router-dom";

export default function Success() {
  return (
    <div className="bg-black text-white min-h-screen flex items-center justify-center px-6">
      <div className="text-center max-w-md">
        <div className="w-20 h-20 bg-green-500 rounded-full flex items-center justify-center mx-auto mb-8">
          <svg className="w-10 h-10 text-black" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={3} d="M5 13l4 4L19 7" />
          </svg>
        </div>
        
        <h1 className="text-3xl font-semibold mb-4">
          Payment Successful!
        </h1>
        
        <p className="text-zinc-400 mb-8">
          Thank you for your purchase. Your order is being processed and will be delivered soon.
        </p>

        <Link
          to="/"
          className="inline-block bg-white text-black px-8 py-3 rounded-xl font-medium hover:opacity-90 transition"
        >
          Continue Shopping
        </Link>
      </div>
    </div>
  );
}
