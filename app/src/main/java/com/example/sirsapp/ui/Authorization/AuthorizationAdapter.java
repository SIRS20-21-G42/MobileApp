package com.example.sirsapp.ui.Authorization;

import android.content.Context;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.recyclerview.widget.RecyclerView;

import com.example.sirsapp.R;

import java.util.List;

public class AuthorizationAdapter extends RecyclerView.Adapter<AuthorizationAdapter.AuthorizationViewHolder> {
    // manages the view holder objects

    private Context context;

    // list of items to be displayed
    private List<AuthorizationItem> list;

    // listener that implements the methods for the interface clickables
    private OnItemClickListener listener;

    public interface OnItemClickListener {
        // interface of the methods for the click actions
        void onItemClick(int position);
        void onItemAccept(int position);
        void onItemDeny(int position);
    }

    public static class AuthorizationViewHolder extends RecyclerView.ViewHolder{
        // Displays a single item in the screen

        TextView authorizationHash;
        Button acceptButton;
        Button declineButton;

        public AuthorizationViewHolder(@NonNull View itemView, OnItemClickListener mListener) {
            super(itemView);
            this.authorizationHash = itemView.findViewById(R.id.authorizationTextView);
            this.acceptButton = itemView.findViewById(R.id.acceptAuthorizationButton);
            this.declineButton = itemView.findViewById(R.id.declineAuthorizationButton);

            setupClickListeners(mListener);
        }

        private void setupClickListeners(OnItemClickListener mListener){
            // listener for the click on the item (text view)
            authorizationHash.setOnClickListener(v -> {
                if (mListener != null){
                    int position = getAdapterPosition();
                    if (position != RecyclerView.NO_POSITION){
                        mListener.onItemClick(position);
                    }
                }
            });

            // listener for the click on the accept button
            acceptButton.setOnClickListener(v -> {
                if (mListener != null){
                    int position = getAdapterPosition();
                    if (position != RecyclerView.NO_POSITION){
                        mListener.onItemAccept(position);
                    }
                }
            });

            // listener for the click on the decline button
            declineButton.setOnClickListener(v -> {
                if (mListener != null){
                    int position = getAdapterPosition();
                    if (position != RecyclerView.NO_POSITION){
                        mListener.onItemDeny(position);
                    }
                }
            });
        }
    }

    public AuthorizationAdapter(Context context, List<AuthorizationItem> list) {
        // constructor
        this.list = list;
        this.context = context;
    }

    public void setOnItemClickListener(OnItemClickListener itemListener){
        // setting the listener
        this.listener = itemListener;
    }

    @NonNull
    @Override
    public AuthorizationViewHolder onCreateViewHolder(@NonNull ViewGroup parent, int viewType) {
        // create each object of the view

        LayoutInflater inflater = LayoutInflater.from(this.context);

        // inflate an element with the base layout
        View view = inflater.inflate(R.layout.authorization_element_layout, parent, false);

        return new AuthorizationViewHolder(view, this.listener);
    }

    @Override
    public void onBindViewHolder(@NonNull AuthorizationViewHolder holder, int position) {
        // assign data to view components

        if (list.get(position).getHash().length() > 5) {
            String text = list.get(position).getHash().substring(0, 5) + "...";
            holder.authorizationHash.setText(text);
        } else {
            holder.authorizationHash.setText(list.get(position).getHash());
        }
    }

    @Override
    public int getItemCount() {
        return list.size();
    }

}
